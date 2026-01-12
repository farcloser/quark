// Package registry provides test utilities for OCI container registries.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/farcloser/quark/dev/filesystem"
)

const (
	// Distribution registry image with pinned digest for reproducibility.
	registryImage    = "ghcr.io/distribution/distribution:3.0.0@sha256:4ba3adf47f5c866e9a29288c758c5328ef03396cb8f5f6454463655fa8bc83e2"
	registryLockFile = "/tmp/quark-test-registry.lock"
	registryInfoFile = "/tmp/quark-test-registry.json"
)

// containerInfo stores the shared container registry information.
type containerInfo struct {
	ContainerID string `json:"containerID"`
	Address     string `json:"address"`
}

// ContainerRegistry represents a Docker container-based OCI registry.
type ContainerRegistry struct {
	// Address is the registry address (e.g., "localhost:5000").
	Address string
}

// EnsureContainerRegistry returns a shared Docker container registry, starting one if needed.
// Uses filesystem locking to coordinate across parallel tests and processes.
// The registry persists across test runs until explicitly stopped or the container dies.
func EnsureContainerRegistry() (*ContainerRegistry, error) {
	// Ensure lock file exists.
	if _, err := os.Stat(registryLockFile); os.IsNotExist(err) {
		if err := os.WriteFile(registryLockFile, nil, filesystem.FilePermissionsPrivate); err != nil {
			return nil, fmt.Errorf("creating registry lock file: %w", err)
		}
	}

	lock, err := filesystem.Lock(registryLockFile)
	if err != nil {
		return nil, fmt.Errorf("acquiring registry lock: %w", err)
	}

	defer filesystem.Unlock(lock)

	// Check if we have an existing registry.
	if info, err := readContainerInfo(); err == nil {
		// Verify it's still running.
		if isAddressReachable(info.Address) {
			return &ContainerRegistry{Address: info.Address}, nil
		}
		// Registry died, clean up the container.
		stopContainer(info.ContainerID)
	}

	// Start a new registry.
	info, err := startContainerRegistry()
	if err != nil {
		return nil, err
	}

	// Save registry info for other processes.
	if err := writeContainerInfo(info); err != nil {
		stopContainer(info.ContainerID)

		return nil, err
	}

	return &ContainerRegistry{Address: info.Address}, nil
}

func readContainerInfo() (*containerInfo, error) {
	data, err := os.ReadFile(registryInfoFile)
	if err != nil {
		return nil, err
	}

	var info containerInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func writeContainerInfo(info *containerInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	return os.WriteFile(registryInfoFile, data, filesystem.FilePermissionsPrivate)
}

func isAddressReachable(address string) bool {
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return false
	}

	_ = conn.Close()

	return true
}

func stopContainer(containerID string) {
	if containerID == "" {
		return
	}

	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), "docker", "rm", "-f", containerID)
	_ = cmd.Run()
}

func startContainerRegistry() (*containerInfo, error) {
	// Find an available port.
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("finding available port: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	address := fmt.Sprintf("localhost:%d", port)

	//nolint:gosec // Test utility.
	cmd := exec.CommandContext(context.Background(), "docker", "run", "-d",
		"-p", fmt.Sprintf("%d:5000", port),
		registryImage)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("starting registry container: %w", err)
	}

	containerID := string(output)
	if len(containerID) > 0 && containerID[len(containerID)-1] == '\n' {
		containerID = containerID[:len(containerID)-1]
	}

	info := &containerInfo{
		ContainerID: containerID,
		Address:     address,
	}

	// Wait for registry to be ready.
	if err := waitForAddress(address); err != nil {
		stopContainer(containerID)

		return nil, err
	}

	return info, nil
}

func waitForAddress(address string) error {
	for i := 0; i < 30; i++ {
		if isAddressReachable(address) {
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("registry not ready after 3 seconds")
}
