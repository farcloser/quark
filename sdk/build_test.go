package sdk_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Timeout is optional.
func TestNewBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		build   func(*sdk.Plan, *sdk.BuildNode) (*sdk.Handle, error)
		wantErr error
	}{
		{
			name: "valid build with all required fields",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Handle, error) {
				return plan.Build(&sdk.BuildArgs{
					Name:    "test-build",
					Context: "/path/to/context",
					Nodes:   []*sdk.BuildNode{buildNode},
					Tag:     "myapp:latest",
				})
			},
			wantErr: nil,
		},
		{
			name: "valid build with explicit dockerfile",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Handle, error) {
				return plan.Build(&sdk.BuildArgs{
					Name:       "test-build-dockerfile",
					Context:    "/path/to/context",
					Dockerfile: "custom.Dockerfile",
					Nodes:      []*sdk.BuildNode{buildNode},
					Tag:        "myapp:latest",
				})
			},
			wantErr: nil,
		},
		{
			name: "valid build with multiple nodes",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Handle, error) {
				node2, err := sdk.NewBuildNode(&sdk.BuildNodeOpts{
					Name:     "test-node-2",
					Endpoint: "ssh://builder@192.168.1.101",
					Platform: sdk.PlatformARM64,
				})
				if err != nil {
					return nil, err
				}

				plan.AddBuildNode(node2)

				return plan.Build(&sdk.BuildArgs{
					Name:    "test-build-multi",
					Context: "/path/to/context",
					Nodes:   []*sdk.BuildNode{buildNode, node2},
					Tag:     "myapp:latest",
				})
			},
			wantErr: nil,
		},
		{
			name: "missing build context",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Handle, error) {
				return plan.Build(&sdk.BuildArgs{
					Name:  "test-build-no-context",
					Nodes: []*sdk.BuildNode{buildNode},
					Tag:   "myapp:latest",
				})
			},
			wantErr: sdk.ErrBuildContextRequired,
		},
		{
			name: "missing build node",
			build: func(plan *sdk.Plan, _ *sdk.BuildNode) (*sdk.Handle, error) {
				return plan.Build(&sdk.BuildArgs{
					Name:    "test-build-no-node",
					Context: "/path/to/context",
					Tag:     "myapp:latest",
				})
			},
			wantErr: sdk.ErrBuildNodeRequired,
		},
		{
			name: "missing tag",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Handle, error) {
				return plan.Build(&sdk.BuildArgs{
					Name:    "test-build-no-tag",
					Context: "/path/to/context",
					Nodes:   []*sdk.BuildNode{buildNode},
				})
			},
			wantErr: sdk.ErrBuildTagRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")

			buildNode, err := sdk.NewBuildNode(&sdk.BuildNodeOpts{
				Name:     "test-node",
				Endpoint: "ssh://builder@192.168.1.100",
				Platform: sdk.PlatformAMD64,
			})
			if err != nil {
				t.Fatalf("Failed to create test build node: %v", err)
			}

			plan.AddBuildNode(buildNode)

			build, err := tt.build(plan, buildNode)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Build() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Build() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("Build() unexpected error = %v", err)

				return
			}

			if build == nil {
				t.Error("Build() returned nil build with nil error")
			}
		})
	}
}

// INTENTION: BuildNode must have endpoint and platform.
func TestNewBuildNode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    *sdk.BuildNodeOpts
		wantErr error
	}{
		{
			name: "valid build node with SSH endpoint",
			args: &sdk.BuildNodeOpts{
				Name:     "test-node-ssh",
				Endpoint: "ssh://builder@192.168.1.100",
				Platform: sdk.PlatformAMD64,
			},
			wantErr: nil,
		},
		{
			name: "valid build node with TCP endpoint",
			args: &sdk.BuildNodeOpts{
				Name:     "test-node-tcp",
				Endpoint: "tcp://192.168.1.100:2376",
				Platform: sdk.PlatformARM64,
			},
			wantErr: nil,
		},
		{
			name: "empty endpoint",
			args: &sdk.BuildNodeOpts{
				Name:     "test-node-empty",
				Endpoint: "",
				Platform: sdk.PlatformAMD64,
			},
			wantErr: sdk.ErrBuildNodeEndpointRequired,
		},
		{
			name: "whitespace-only endpoint",
			args: &sdk.BuildNodeOpts{
				Name:     "test-node-whitespace",
				Endpoint: "   ",
				Platform: sdk.PlatformAMD64,
			},
			wantErr: sdk.ErrBuildNodeEndpointRequired,
		},
		{
			name: "missing platform",
			args: &sdk.BuildNodeOpts{
				Name:     "test-node-no-platform",
				Endpoint: "ssh://builder@192.168.1.100",
			},
			wantErr: sdk.ErrBuildNodePlatformRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			node, err := sdk.NewBuildNode(tt.args)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("NewBuildNode() error = nil, wantErr %v", tt.wantErr)

					return
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("NewBuildNode() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Errorf("NewBuildNode() unexpected error = %v", err)

				return
			}

			if node == nil {
				t.Error("NewBuildNode() returned nil node with nil error")
			}
		})
	}
}
