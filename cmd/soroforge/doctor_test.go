package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/soroworks/soroforge/internal/config"
	"github.com/soroworks/soroforge/internal/stellar"
	"github.com/soroworks/soroforge/internal/store"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the whole doctor checklist against fakes: a MockClient
// for every network, an in-memory store, and a scripted migrator. They use
// t.Setenv, so they cannot run in parallel.

type fakeMigrator struct {
	version uint
	dirty   bool
	latest  uint
	err     error
}

func (m *fakeMigrator) Version() (uint, bool, error) { return m.version, m.dirty, m.err }
func (m *fakeMigrator) Latest() (uint, error)        { return m.latest, nil }
func (m *fakeMigrator) Close() error                 { return nil }

// doctorEnv clears every variable the doctor reads, so a developer's shell
// cannot change the outcome, then applies the overrides.
func doctorEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	for _, name := range []string{
		config.EnvDatabaseURL, config.EnvSecretKey, config.EnvKeystorePath,
		config.EnvSignerCommand, config.EnvSignerPublicKey, config.EnvCosignerKeystores,
		config.EnvConfigPath, config.EnvLogFormat,
	} {
		t.Setenv(name, overrides[name])
	}
}

// writeDoctorConfig writes a one-network config whose contract points at a
// real WASM file, and returns the config path.
func writeDoctorConfig(t *testing.T, friendbot bool) string {
	t.Helper()
	dir := t.TempDir()
	wasm := filepath.Join(dir, "counter.wasm")
	require.NoError(t, os.WriteFile(wasm, []byte{0x00, 0x61, 0x73, 0x6d, 0x01}, 0o600))

	friendbotLine := ""
	if friendbot {
		friendbotLine = "\n    friendbot_url: https://friendbot.example.org"
	}
	body := fmt.Sprintf(`
version: 1
default_network: testnet
networks:
  testnet:
    rpc_url: https://testnet.example.org
    passphrase: "Test SDF Network ; September 2015"%s
contracts:
  counter:
    wasm: %q
`, friendbotLine, wasm)
	path := filepath.Join(dir, config.DefaultFilename)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func fakeDoctorDeps(client *stellar.MockClient, migrator *fakeMigrator) doctorDeps {
	return doctorDeps{
		clients: func(string, config.Network) (stellar.Client, error) { return client, nil },
		openStore: func(context.Context, string) (store.Store, error) {
			return store.NewMemoryStore(), nil
		},
		openMigrator: func(string) (schemaMigrator, error) { return migrator, nil },
	}
}

func checksByName(report doctorReport) map[string]doctorCheck {
	byName := map[string]doctorCheck{}
	for _, c := range report.Checks {
		byName[c.Name] = c
	}
	return byName
}

func TestDoctorAllChecksPass(t *testing.T) {
	seed := keypair.MustRandom()
	doctorEnv(t, map[string]string{
		config.EnvDatabaseURL: "postgres://doctor@localhost/soroforge",
		config.EnvSecretKey:   seed.Seed(),
	})
	client := stellar.NewMockClient()
	require.NoError(t, client.SetAccountEntry(seed.Address(), 100_000_000, 7))

	report := runDoctor(context.Background(),
		fakeDoctorDeps(client, &fakeMigrator{version: 10, latest: 10}),
		doctorOptions{configPath: writeDoctorConfig(t, false)})

	names := make([]string, 0, len(report.Checks))
	for _, c := range report.Checks {
		names = append(names, c.Name)
		assert.Equal(t, doctorPass, c.Status, "%s: %s", c.Name, c.Detail)
		assert.Empty(t, c.Fix, "a passing check has nothing to fix")
	}
	assert.Equal(t, []string{
		"config", "wasm", "network:testnet", "database", "migrations", "signer", "deployer",
	}, names)
	assert.True(t, report.OK)
	assert.Equal(t, 7, report.Passed)
	assert.Contains(t, checksByName(report)["deployer"].Detail, "10.0000000 XLM")

	require.NoError(t, reportDoctor(&bytes.Buffer{}, report, false))
}

func TestDoctorSkipsWhatIsNotConfigured(t *testing.T) {
	doctorEnv(t, nil)
	deps := fakeDoctorDeps(stellar.NewMockClient(), nil)
	deps.openStore = func(context.Context, string) (store.Store, error) {
		t.Fatal("the database was opened without a DATABASE_URL")
		return nil, nil
	}
	deps.openMigrator = func(string) (schemaMigrator, error) {
		t.Fatal("the migrator was opened without a DATABASE_URL")
		return nil, nil
	}

	report := runDoctor(context.Background(), deps,
		doctorOptions{configPath: writeDoctorConfig(t, false)})

	byName := checksByName(report)
	for _, name := range []string{"database", "migrations", "signer", "deployer"} {
		assert.Equal(t, doctorSkip, byName[name].Status, name)
		assert.NotEmpty(t, byName[name].Fix, "%s: a skipped check says how to enable it", name)
	}
	assert.Contains(t, byName["database"].Fix, config.EnvDatabaseURL)
	assert.Contains(t, byName["signer"].Fix, config.EnvSecretKey)
	assert.True(t, report.OK, "skipped checks must not fail the run")
	assert.Zero(t, report.Failed)
	require.NoError(t, reportDoctor(&bytes.Buffer{}, report, false))
}

func TestDoctorReportsEveryFailureWithAFix(t *testing.T) {
	seed := keypair.MustRandom()
	doctorEnv(t, map[string]string{
		config.EnvDatabaseURL: "postgres://doctor@localhost/soroforge",
		config.EnvSecretKey:   seed.Seed(),
	})
	path := writeDoctorConfig(t, true)
	// Break the artifact the config points at.
	cfg, err := config.Load(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfg.WasmPath(cfg.Contracts["counter"]), []byte("not wasm"), 0o600))

	// The network answers, so the deployer check runs and finds no account.
	client := stellar.NewMockClient()
	report := runDoctor(context.Background(),
		fakeDoctorDeps(client, &fakeMigrator{version: 8, latest: 10}),
		doctorOptions{configPath: path})

	byName := checksByName(report)
	assert.Equal(t, doctorFail, byName["wasm"].Status)
	assert.Contains(t, byName["wasm"].Detail, "magic bytes")
	assert.Equal(t, doctorFail, byName["migrations"].Status)
	assert.Contains(t, byName["migrations"].Detail, "version 8; the latest is 10")
	assert.Equal(t, "run `soroforge migrate up`", byName["migrations"].Fix)
	assert.Equal(t, doctorFail, byName["deployer"].Status)
	assert.Contains(t, byName["deployer"].Fix, "soroforge fund")
	assert.Equal(t, doctorPass, byName["network:testnet"].Status)
	assert.Equal(t, doctorPass, byName["signer"].Status)
	assert.False(t, report.OK)
	assert.Equal(t, 3, report.Failed)

	var buf bytes.Buffer
	err = reportDoctor(&buf, report, false)
	require.Error(t, err, "a failed check must make the command exit non-zero")
	assert.Contains(t, err.Error(), "3 of 7 doctor check(s) failed")
	text := buf.String()
	assert.Contains(t, text, "FAIL  migrations")
	assert.Contains(t, text, "fix: run `soroforge migrate up`")
	assert.Contains(t, text, "4 passed, 3 failed, 0 skipped.")
}

func TestDoctorNetworkMismatchSkipsTheDeployerCheck(t *testing.T) {
	seed := keypair.MustRandom()
	doctorEnv(t, map[string]string{config.EnvSecretKey: seed.Seed()})
	client := stellar.NewMockClient()
	client.ReportPassphrase = "Public Global Stellar Network ; September 2015"

	report := runDoctor(context.Background(), fakeDoctorDeps(client, nil),
		doctorOptions{configPath: writeDoctorConfig(t, false)})

	byName := checksByName(report)
	network := byName["network:testnet"]
	assert.Equal(t, doctorFail, network.Status)
	assert.Contains(t, network.Fix, "networks.testnet.passphrase")
	assert.Equal(t, doctorSkip, byName["deployer"].Status,
		"an unusable network must not be reported as an unfunded account")
	assert.Contains(t, byName["deployer"].Detail, "testnet is not reachable")
}

func TestDoctorStillChecksTheEnvironmentWhenConfigFails(t *testing.T) {
	doctorEnv(t, map[string]string{config.EnvDatabaseURL: "sqlite:///tmp/doctor.db"})

	report := runDoctor(context.Background(),
		fakeDoctorDeps(stellar.NewMockClient(), &fakeMigrator{version: 10, latest: 10}),
		doctorOptions{configPath: filepath.Join(t.TempDir(), "missing.yaml")})

	byName := checksByName(report)
	assert.Equal(t, doctorFail, byName["config"].Status)
	assert.Contains(t, byName["config"].Fix, "soroforge init")
	assert.Equal(t, doctorSkip, byName["wasm"].Status)
	assert.Equal(t, doctorSkip, byName["network:*"].Status)
	assert.Equal(t, doctorPass, byName["database"].Status)
	assert.Equal(t, doctorPass, byName["migrations"].Status)
	assert.Equal(t, doctorSkip, byName["signer"].Status)
	assert.Equal(t, doctorSkip, byName["deployer"].Status)
	assert.False(t, report.OK)
}

func TestDoctorNeverPrintsTheDatabasePassword(t *testing.T) {
	const databaseURL = "postgres://soroforge:hunter2@db.internal:5432/soroforge"
	doctorEnv(t, map[string]string{config.EnvDatabaseURL: databaseURL})
	deps := fakeDoctorDeps(stellar.NewMockClient(), nil)
	deps.openStore = func(context.Context, string) (store.Store, error) {
		return nil, errors.New("dial " + databaseURL + ": connection refused")
	}

	report := runDoctor(context.Background(), deps,
		doctorOptions{configPath: writeDoctorConfig(t, false)})

	byName := checksByName(report)
	assert.Equal(t, doctorFail, byName["database"].Status)
	assert.Contains(t, byName["database"].Detail, "connection refused")
	assert.Equal(t, doctorSkip, byName["migrations"].Status)

	var buf bytes.Buffer
	require.Error(t, reportDoctor(&buf, report, true))
	assert.NotContains(t, buf.String(), "hunter2")
}

func TestDoctorMigrationStates(t *testing.T) {
	cases := map[string]struct {
		migrator *fakeMigrator
		status   string
		detail   string
	}{
		"current": {&fakeMigrator{version: 10, latest: 10}, doctorPass, "latest version, 10"},
		"behind":  {&fakeMigrator{version: 0, latest: 10}, doctorFail, "version 0; the latest is 10"},
		"dirty":   {&fakeMigrator{version: 9, dirty: true, latest: 10}, doctorFail, "dirty"},
		"ahead":   {&fakeMigrator{version: 11, latest: 10}, doctorFail, "newer than this binary"},
		"error":   {&fakeMigrator{err: errors.New("permission denied"), latest: 10}, doctorFail, "permission denied"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := checkDoctorMigrations(fakeDoctorDeps(nil, tc.migrator), "sqlite:///x.db",
				func(err error) string { return err.Error() })
			assert.Equal(t, tc.status, c.Status)
			assert.Contains(t, c.Detail, tc.detail)
			if tc.status == doctorFail {
				assert.NotEmpty(t, c.Fix)
			}
		})
	}
}

func TestDoctorJSONEmitsTheChecklist(t *testing.T) {
	doctorEnv(t, nil)
	report := runDoctor(context.Background(), fakeDoctorDeps(stellar.NewMockClient(), nil),
		doctorOptions{configPath: writeDoctorConfig(t, false)})

	var buf bytes.Buffer
	require.NoError(t, reportDoctor(&buf, report, true))

	var decoded struct {
		OK      bool `json:"ok"`
		Skipped int  `json:"skipped"`
		Checks  []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Detail string `json:"detail"`
			Fix    string `json:"fix"`
		} `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.True(t, decoded.OK)
	assert.Equal(t, 4, decoded.Skipped)
	require.Len(t, decoded.Checks, 7)
	assert.Equal(t, "config", decoded.Checks[0].Name)
	assert.Equal(t, "pass", decoded.Checks[0].Status)
	assert.Equal(t, "skip", decoded.Checks[3].Status)
	assert.NotEmpty(t, decoded.Checks[3].Fix)
}

func TestDoctorCommandIsRegistered(t *testing.T) {
	cmd, _, err := newRootCmd().Find([]string{"doctor"})
	require.NoError(t, err)
	assert.Equal(t, "doctor", cmd.Name())
	require.NotNil(t, cmd.Flags().Lookup("timeout"))
}
