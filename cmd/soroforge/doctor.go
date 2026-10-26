package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/soroworks/soroforge/internal/config"
	"github.com/soroworks/soroforge/internal/deploy"
	"github.com/soroworks/soroforge/internal/netcheck"
	"github.com/soroworks/soroforge/internal/readiness"
	"github.com/soroworks/soroforge/internal/stellar"
	"github.com/soroworks/soroforge/internal/store"
	"github.com/spf13/cobra"
)

// Doctor check outcomes. A skipped check needed something that is not
// configured (no DATABASE_URL, no signer) or depended on a check that failed;
// it is reported so the gap is visible, but it does not fail the run.
const (
	doctorPass = "pass"
	doctorFail = "fail"
	doctorSkip = "skip"
)

// doctorCheck is one line of the `soroforge doctor` checklist.
type doctorCheck struct {
	// Name is a stable identifier: config, wasm, network:<name>, database,
	// migrations, signer, or deployer.
	Name   string `json:"name"`
	Status string `json:"status"`

	// Detail says what was found, in one line.
	Detail string `json:"detail"`

	// Fix is the one-line remedy for a failed or skipped check. It is empty
	// when the check passed.
	Fix string `json:"fix,omitempty"`
}

// doctorReport is the full checklist, as `--json` emits it.
type doctorReport struct {
	OK      bool          `json:"ok"`
	Passed  int           `json:"passed"`
	Failed  int           `json:"failed"`
	Skipped int           `json:"skipped"`
	Checks  []doctorCheck `json:"checks"`
}

// schemaMigrator is the part of store.Migrator the doctor reads. It is an
// interface so tests can report any schema state without a database.
type schemaMigrator interface {
	Version() (version uint, dirty bool, err error)
	Latest() (uint, error)
	Close() error
}

// doctorDeps are the doctor's connections to the outside world. Production
// uses the same constructors as every other command; tests substitute fakes so
// the whole checklist runs without a network or a database.
type doctorDeps struct {
	clients      deploy.ClientFactory
	openStore    func(ctx context.Context, databaseURL string) (store.Store, error)
	openMigrator func(databaseURL string) (schemaMigrator, error)
}

func defaultDoctorDeps() doctorDeps {
	return doctorDeps{
		clients:   deploy.DefaultClientFactory,
		openStore: store.Open,
		openMigrator: func(databaseURL string) (schemaMigrator, error) {
			return store.NewMigrator(databaseURL)
		},
	}
}

// doctorOptions are the inputs that come from flags.
type doctorOptions struct {
	configPath string
	network    string
	timeout    time.Duration
}

func newDoctorCmd() *cobra.Command {
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run every preflight check at once",
		Long: `Check everything a deploy depends on and print one checklist:

  config      soroforge.yaml loads and validates
  wasm        every contract's WASM artifact exists and is WebAssembly
  network:*   each network's RPC answers and serves the configured passphrase
  database    DATABASE_URL is reachable and its schema can be queried
  migrations  the schema is at the latest migration this binary ships
  signer      a signing key or external signer is configured and loads
  deployer    the deployer account is funded on the target network

Every check runs even when an earlier one fails, so one invocation lists every
problem. Each failure prints a one-line fix. A check that needs something not
configured — no DATABASE_URL, no signer — is reported as skipped, not failed.

The target network for the deployer check is --network, or default_network.

Exit codes:
  0  no check failed (some may have been skipped)
  1  at least one check failed`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := runDoctor(cmd.Context(), defaultDoctorDeps(), doctorOptions{
				configPath: flags.configPath,
				network:    flags.network,
				timeout:    timeout,
			})
			return reportDoctor(out(), report, flags.jsonOutput)
		},
	}

	cmd.Flags().DurationVar(&timeout, "timeout", netcheck.DefaultTimeout,
		"timeout for each network, database, and account probe")
	return cmd
}

// reportDoctor prints the checklist and turns any failure into an error, which
// main maps to exit code 1.
func reportDoctor(w io.Writer, report doctorReport, asJSON bool) error {
	var err error
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		err = enc.Encode(report)
	} else {
		err = printDoctorReport(w, report)
	}
	if err != nil {
		return err
	}
	if !report.OK {
		return fmt.Errorf("%d of %d doctor check(s) failed", report.Failed, len(report.Checks))
	}
	return nil
}

// runDoctor runs every check and returns the checklist. It never stops early:
// a check whose prerequisite failed is skipped with the reason, so the report
// always has the same shape.
func runDoctor(ctx context.Context, deps doctorDeps, opts doctorOptions) doctorReport {
	if opts.timeout <= 0 {
		opts.timeout = netcheck.DefaultTimeout
	}
	var checks []doctorCheck
	add := func(c doctorCheck) { checks = append(checks, c) }

	// The network probes feed the deployer check: an unreachable network
	// would only make it fail again with a less useful message.
	reachable := map[string]bool{}

	cfg, cfgErr := config.Load(opts.configPath)
	if cfgErr != nil {
		add(doctorCheck{
			Name: "config", Status: doctorFail, Detail: cfgErr.Error(),
			Fix: "fix the reported field in soroforge.yaml, or run `soroforge init` to create one",
		})
		add(skipped("wasm", "configuration did not load"))
		add(skipped("network:*", "configuration did not load"))
	} else {
		add(doctorCheck{Name: "config", Status: doctorPass,
			Detail: fmt.Sprintf("%d network(s) and %d contract(s) configured", len(cfg.Networks), len(cfg.Contracts))})
		add(checkDoctorWasm(cfg))
		for _, res := range netcheck.Check(ctx, cfg.Networks, netcheck.ClientFactory(deps.clients), opts.timeout) {
			reachable[res.Network] = res.OK
			add(networkCheck(res))
		}
	}

	// The database and signer depend only on the environment, so they are
	// still checked when soroforge.yaml is broken.
	env := config.LoadEnv()
	if cfg != nil {
		env = cfg.Env
	}
	for _, c := range checkDoctorDatabase(ctx, deps, env.DatabaseURL, opts.timeout) {
		add(c)
	}

	signerCfg := cfg
	if signerCfg == nil {
		signerCfg = &config.Config{Env: env}
	}
	signerCheck, signer := checkDoctorSigner(signerCfg)
	add(signerCheck)

	switch {
	case cfg == nil:
		add(skipped("deployer", "configuration did not load"))
	case signer == nil:
		add(skipped("deployer", "no usable signer"))
	default:
		add(checkDoctorDeployer(ctx, deps, cfg, signer, opts, reachable))
	}

	return newDoctorReport(checks)
}

func newDoctorReport(checks []doctorCheck) doctorReport {
	report := doctorReport{Checks: checks}
	for _, c := range checks {
		switch c.Status {
		case doctorPass:
			report.Passed++
		case doctorFail:
			report.Failed++
		default:
			report.Skipped++
		}
	}
	report.OK = report.Failed == 0
	return report
}

// skipped reports a check whose prerequisite did not pass. The remedy is the
// prerequisite's own fix, so it points there rather than repeating it.
func skipped(name, why string) doctorCheck {
	return doctorCheck{Name: name, Status: doctorSkip, Detail: why,
		Fix: "resolve the check above, then run `soroforge doctor` again"}
}

func checkDoctorWasm(cfg *config.Config) doctorCheck {
	if len(cfg.Contracts) == 0 {
		return doctorCheck{Name: "wasm", Status: doctorSkip, Detail: "no contracts are configured",
			Fix: "add a contract under contracts: in soroforge.yaml"}
	}
	if problems := checkWasmArtifacts(cfg); len(problems) > 0 {
		return doctorCheck{Name: "wasm", Status: doctorFail, Detail: strings.Join(problems, "; "),
			Fix: "build the contracts (for example `stellar contract build`) or correct contracts.<alias>.wasm"}
	}
	return doctorCheck{Name: "wasm", Status: doctorPass,
		Detail: fmt.Sprintf("%d WASM artifact(s) present", len(cfg.Contracts))}
}

// networkCheck turns a netcheck result into a checklist line. The detail uses
// the redacted URL and the already-redacted error, never the raw rpc_url.
func networkCheck(res netcheck.Result) doctorCheck {
	c := doctorCheck{Name: "network:" + res.Network}
	if res.OK {
		c.Status = doctorPass
		c.Detail = fmt.Sprintf("%s answered at ledger %d in %s; passphrase matches",
			res.RedactedURL, res.LatestLedger, formatLatency(res.Latency))
		return c
	}
	c.Status = doctorFail
	c.Detail = fmt.Sprintf("%s: %s", res.RedactedURL, res.Error)
	if res.PassphraseVerified && !res.PassphraseMatch {
		c.Fix = fmt.Sprintf("set networks.%s.passphrase to the endpoint's passphrase, or point rpc_url at the intended network", res.Network)
	} else {
		c.Fix = fmt.Sprintf("check networks.%s.rpc_url and that the endpoint is up; `soroforge networks` shows details", res.Network)
	}
	return c
}

// checkDoctorDatabase reports the database and migrations checks. Reachability
// goes through the readiness checker — the same query `/ready` runs — and the
// schema version through the migrator `soroforge migrate` uses.
func checkDoctorDatabase(ctx context.Context, deps doctorDeps, databaseURL string, timeout time.Duration) []doctorCheck {
	if databaseURL == "" {
		why := config.EnvDatabaseURL + " is not set"
		fix := "set " + config.EnvDatabaseURL + " (postgres://... or sqlite://...) to record deployment history"
		return []doctorCheck{
			{Name: "database", Status: doctorSkip, Detail: why, Fix: fix},
			{Name: "migrations", Status: doctorSkip, Detail: why, Fix: fix},
		}
	}
	// Driver errors can echo the connection string; never print its password.
	redact := func(err error) string {
		return strings.ReplaceAll(err.Error(), databaseURL, netcheck.RedactURL(databaseURL))
	}

	database := doctorCheck{Name: "database"}
	openCtx, cancel := context.WithTimeout(ctx, timeout)
	st, err := deps.openStore(openCtx, databaseURL)
	cancel()
	if err != nil {
		database.Status = doctorFail
		database.Detail = redact(err)
		database.Fix = "check " + config.EnvDatabaseURL + " and that the database server is running and accepts the credentials"
		return []doctorCheck{database, skipped("migrations", "database is unreachable")}
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Warn("closing store", "error", err)
		}
	}()

	// No networks: only the database dependency is probed here, because the
	// network checks above already went through netcheck.
	checker, err := readiness.New(readiness.Options{
		Store:   st,
		Config:  &config.Config{},
		Clients: readiness.ClientFactory(deps.clients),
		Timeout: timeout,
	})
	if err != nil {
		database.Status = doctorFail
		database.Detail = err.Error()
		database.Fix = "report this as a bug"
	} else if dep := checker.Check(ctx).Dependencies[0]; dep.OK {
		database.Status = doctorPass
		database.Detail = "connected and queried deployment history"
	} else {
		database.Status = doctorFail
		database.Detail = strings.ReplaceAll(dep.Error, databaseURL, netcheck.RedactURL(databaseURL))
		database.Fix = "run `soroforge migrate up`, and check the database user can read the schema"
	}

	return []doctorCheck{database, checkDoctorMigrations(deps, databaseURL, redact)}
}

func checkDoctorMigrations(deps doctorDeps, databaseURL string, redact func(error) string) doctorCheck {
	c := doctorCheck{Name: "migrations", Status: doctorFail}
	m, err := deps.openMigrator(databaseURL)
	if err != nil {
		c.Detail = redact(err)
		c.Fix = "check " + config.EnvDatabaseURL + "; `soroforge migrate version` shows the same error"
		return c
	}
	defer func() {
		if err := m.Close(); err != nil {
			slog.Warn("closing migrator", "error", err)
		}
	}()

	latest, err := m.Latest()
	if err != nil {
		c.Detail = err.Error()
		c.Fix = "report this as a bug: the binary ships no migrations"
		return c
	}
	version, dirty, err := m.Version()
	switch {
	case err != nil:
		c.Detail = redact(err)
		c.Fix = "check " + config.EnvDatabaseURL + "; `soroforge migrate version` shows the same error"
	case dirty:
		c.Detail = fmt.Sprintf("schema is at version %d and dirty: a migration failed partway", version)
		c.Fix = "repair the failed migration by hand, then run `soroforge migrate up`"
	case version < latest:
		c.Detail = fmt.Sprintf("schema is at version %d; the latest is %d", version, latest)
		c.Fix = "run `soroforge migrate up`"
	case version > latest:
		c.Detail = fmt.Sprintf("schema is at version %d, newer than this binary's latest, %d", version, latest)
		c.Fix = "upgrade soroforge to the version that migrated this database"
	default:
		c.Status = doctorPass
		c.Detail = fmt.Sprintf("schema is at the latest version, %d", latest)
	}
	return c
}

// checkDoctorSigner builds the signer exactly as deploy would. It returns the
// signer for the deployer check, or nil when none is usable.
func checkDoctorSigner(cfg *config.Config) (doctorCheck, stellar.Signer) {
	signer, err := buildSigner(cfg, false)
	switch {
	case err != nil:
		return doctorCheck{Name: "signer", Status: doctorFail, Detail: err.Error(),
			Fix: "correct the signing configuration named above (see README security notes)"}, nil
	case signer == nil:
		return doctorCheck{Name: "signer", Status: doctorSkip, Detail: "no signing key configured",
			Fix: fmt.Sprintf("set %s or %s, or %s with %s",
				config.EnvSecretKey, config.EnvKeystorePath, config.EnvSignerCommand, config.EnvSignerPublicKey)}, nil
	}
	detail := "signs as " + signer.Address()
	if source := cfg.Env.SigningSource(); source != "" {
		detail += " (key source: " + source + ")"
	}
	return doctorCheck{Name: "signer", Status: doctorPass, Detail: detail}, signer
}

// checkDoctorDeployer reports whether the deployer account exists on the
// target network, through the same WhoAmI `soroforge whoami` runs.
func checkDoctorDeployer(
	ctx context.Context,
	deps doctorDeps,
	cfg *config.Config,
	signer stellar.Signer,
	opts doctorOptions,
	reachable map[string]bool,
) doctorCheck {
	c := doctorCheck{Name: "deployer", Status: doctorFail}

	name, network, err := cfg.Network(opts.network)
	if err != nil {
		c.Detail = err.Error()
		c.Fix = "pass --network with a configured network, or fix default_network"
		return c
	}
	if !reachable[name] {
		return skipped("deployer", fmt.Sprintf("network %s is not reachable", name))
	}

	service, err := deploy.New(deploy.Options{
		Config:  cfg,
		Store:   store.NewMemoryStore(),
		Signer:  signer,
		Clients: deps.clients,
		Log:     slog.Default(),
	})
	if err != nil {
		c.Detail = err.Error()
		c.Fix = "report this as a bug"
		return c
	}
	defer func() { _ = service.Close() }()

	probeCtx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	who, err := service.WhoAmI(probeCtx, deploy.WhoAmIRequest{Network: name})
	if err != nil {
		c.Detail = err.Error()
		c.Fix = "check the network's RPC endpoint; `soroforge whoami` shows the same error"
		return c
	}
	if !who.Funded {
		c.Detail = who.Detail
		if network.FriendbotURL != "" {
			c.Fix = "run `soroforge fund` to create the account from Friendbot"
		} else {
			c.Fix = fmt.Sprintf("send XLM to %s on %s to create the account", who.Address, name)
		}
		return c
	}
	c.Status = doctorPass
	c.Detail = fmt.Sprintf("%s holds %s XLM on %s", who.Address, who.BalanceXLM, name)
	return c
}

// printDoctorReport renders the checklist: a status and detail per check, and
// the fix underneath anything that did not pass.
func printDoctorReport(w io.Writer, report doctorReport) error {
	width := 0
	for _, c := range report.Checks {
		width = max(width, len(c.Name))
	}
	for _, c := range report.Checks {
		if _, err := fmt.Fprintf(w, "%-4s  %-*s  %s\n",
			strings.ToUpper(c.Status), width, c.Name, oneLine(c.Detail)); err != nil {
			return err
		}
		if c.Status != doctorPass && c.Fix != "" {
			if _, err := fmt.Fprintf(w, "      %-*s  fix: %s\n", width, "", c.Fix); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(w, "\n%d passed, %d failed, %d skipped.\n", report.Passed, report.Failed, report.Skipped)
	return err
}

// oneLine collapses a multi-line error (config validation lists every
// problem) so each check stays on one row.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
