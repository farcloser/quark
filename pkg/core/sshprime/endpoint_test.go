package sshprime_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kevinburke/ssh_config"

	"github.com/farcloser/quark/pkg/core/sshprime"
	"github.com/farcloser/quark/pkg/fault"
)

// testConfigPath is set by TestMain before any ssh_config access.
//
//nolint:gochecknoglobals // Required for test setup - ConfigFinder closure captures this.
var testConfigPath string

//nolint:gochecknoinits // Required to set ConfigFinder before any ssh_config.Get() calls.
func init() {
	// Set custom config finder BEFORE any ssh_config.Get() calls.
	// The function is called lazily when config is first accessed.
	ssh_config.DefaultUserSettings.ConfigFinder(func() string {
		return testConfigPath
	})
}

func TestMain(m *testing.M) {
	// Create temp dir with SSH config.
	tmpHome, err := os.MkdirTemp("", "ssh-test-home")
	if err != nil {
		panic("failed to create temp home: " + err.Error())
	}

	sshDir := filepath.Join(tmpHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		panic("failed to create .ssh dir: " + err.Error())
	}

	configContent := `Host myserver
    Hostname actual.example.com
    User configuser
    Port 2222

Host badport
    Port notanumber
`

	testConfigPath = filepath.Join(sshDir, "config")

	if err := os.WriteFile(testConfigPath, []byte(configContent), 0o600); err != nil {
		panic("failed to write ssh config: " + err.Error())
	}

	defer func() { _ = os.RemoveAll(tmpHome) }()

	m.Run()
}

func TestResolve_SimpleHost(t *testing.T) {
	t.Parallel()

	endpoint, err := sshprime.Resolve("example.com", false)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if endpoint.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", endpoint.Host)
	}

	if endpoint.Port != 22 {
		t.Errorf("expected port 22, got %d", endpoint.Port)
	}
}

func TestResolve_UserAtHost(t *testing.T) {
	t.Parallel()

	endpoint, err := sshprime.Resolve("myuser@example.com", false)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if endpoint.User != "myuser" {
		t.Errorf("expected user 'myuser', got %q", endpoint.User)
	}

	if endpoint.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", endpoint.Host)
	}

	if endpoint.Port != 22 {
		t.Errorf("expected port 22, got %d", endpoint.Port)
	}
}

func TestResolve_FallbackToUSEREnv(t *testing.T) {
	t.Setenv("USER", "envuser")
	t.Setenv("LOGNAME", "")

	endpoint, err := sshprime.Resolve("example.com", false)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if endpoint.User != "envuser" {
		t.Errorf("expected user 'envuser' from USER env, got %q", endpoint.User)
	}
}

func TestResolve_FallbackToLOGNAMEEnv(t *testing.T) {
	t.Setenv("USER", "")
	t.Setenv("LOGNAME", "loguser")

	endpoint, err := sshprime.Resolve("example.com", false)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if endpoint.User != "loguser" {
		t.Errorf("expected user 'loguser' from LOGNAME env, got %q", endpoint.User)
	}
}

func TestResolve_NoUserAvailable_ReturnsError(t *testing.T) {
	t.Setenv("USER", "")
	t.Setenv("LOGNAME", "")

	_, err := sshprime.Resolve("example.com", false)
	if err == nil {
		t.Fatal("expected error when no user available, got nil")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestResolve_WithSSHConfig(t *testing.T) {
	t.Parallel()

	// Uses config set up in TestMain.
	endpoint, err := sshprime.Resolve("myserver", true)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if endpoint.User != "configuser" {
		t.Errorf("expected user 'configuser' from config, got %q", endpoint.User)
	}

	if endpoint.Host != "actual.example.com" {
		t.Errorf("expected host 'actual.example.com' from config, got %q", endpoint.Host)
	}

	if endpoint.Port != 2222 {
		t.Errorf("expected port 2222 from config, got %d", endpoint.Port)
	}
}

func TestResolve_ConfigIgnoredWhenUseConfigFalse(t *testing.T) {
	t.Setenv("USER", "envuser")

	// Uses config set up in TestMain, but useConfig=false.
	endpoint, err := sshprime.Resolve("myserver", false)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Config should be ignored.
	if endpoint.User != "envuser" {
		t.Errorf("expected user 'envuser' (config ignored), got %q", endpoint.User)
	}

	if endpoint.Port != 22 {
		t.Errorf("expected default port 22 (config ignored), got %d", endpoint.Port)
	}
}

func TestResolve_UserInEndpointOverridesConfig(t *testing.T) {
	t.Parallel()

	// Uses config set up in TestMain.
	endpoint, err := sshprime.Resolve("explicituser@myserver", true)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if endpoint.User != "explicituser" {
		t.Errorf("expected user 'explicituser' from endpoint, got %q", endpoint.User)
	}
}

func TestResolve_InvalidPortInConfig_FallsBackToDefault(t *testing.T) {
	t.Parallel()

	// ssh_config.Get() validates Port values and returns "" for non-numeric ports.
	// The "badport" host has "Port notanumber" in config, which ssh_config rejects.
	// Resolve should fall back to default port 22.
	endpoint, err := sshprime.Resolve("badport", true)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if endpoint.Port != 22 {
		t.Errorf("expected default port 22 for invalid config port, got %d", endpoint.Port)
	}
}
