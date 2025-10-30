//nolint:varnamelen
package sdk_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/farcloser/quark/sdk"
)

// - Timeout is optional.
func TestBuildBuilder_Build(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		build   func(*sdk.Plan, *sdk.BuildNode) (*sdk.Build, error)
		wantErr error
	}{
		{
			name: "valid build with all required fields",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Build, error) {
				return plan.Build("test-build").
					Context("/path/to/context").
					Node(buildNode).
					Tag("myapp:latest").
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid build with explicit dockerfile",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Build, error) {
				return plan.Build("test-build-dockerfile").
					Context("/path/to/context").
					Dockerfile("custom.Dockerfile").
					Node(buildNode).
					Tag("myapp:latest").
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid build with multiple nodes",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Build, error) {
				node2, err := plan.BuildNode("test-node-2").
					Endpoint("ssh://builder@192.168.1.101").
					Platform(sdk.PlatformARM64).
					Build()
				if err != nil {
					return nil, fmt.Errorf("failed to create test node: %w", err)
				}

				return plan.Build("test-build-multi").
					Context("/path/to/context").
					Node(buildNode).
					Node(node2).
					Tag("myapp:latest").
					Build()
			},
			wantErr: nil,
		},
		{
			name: "missing build context",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Build, error) {
				return plan.Build("test-build-no-context").
					Node(buildNode).
					Tag("myapp:latest").
					Build()
			},
			wantErr: sdk.ErrBuildContextRequired,
		},
		{
			name: "missing build node",
			build: func(plan *sdk.Plan, _ *sdk.BuildNode) (*sdk.Build, error) {
				return plan.Build("test-build-no-node").
					Context("/path/to/context").
					Tag("myapp:latest").
					Build()
			},
			wantErr: sdk.ErrBuildNodeRequired,
		},
		{
			name: "missing tag",
			build: func(plan *sdk.Plan, buildNode *sdk.BuildNode) (*sdk.Build, error) {
				return plan.Build("test-build-no-tag").
					Context("/path/to/context").
					Node(buildNode).
					Build()
			},
			wantErr: sdk.ErrBuildTagRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")

			buildNode, err := plan.BuildNode("test-node").
				Endpoint("ssh://builder@192.168.1.100").
				Platform(sdk.PlatformAMD64).
				Build()
			if err != nil {
				t.Fatalf("Failed to create test build node: %v", err)
			}

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
func TestBuildNodeBuilder_Build(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		build   func(*sdk.Plan) (*sdk.BuildNode, error)
		wantErr error
	}{
		{
			name: "valid build node with SSH endpoint",
			build: func(plan *sdk.Plan) (*sdk.BuildNode, error) {
				return plan.BuildNode("test-node-ssh").
					Endpoint("ssh://builder@192.168.1.100").
					Platform(sdk.PlatformAMD64).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "valid build node with TCP endpoint",
			build: func(plan *sdk.Plan) (*sdk.BuildNode, error) {
				return plan.BuildNode("test-node-tcp").
					Endpoint("tcp://192.168.1.100:2376").
					Platform(sdk.PlatformARM64).
					Build()
			},
			wantErr: nil,
		},
		{
			name: "empty endpoint",
			build: func(plan *sdk.Plan) (*sdk.BuildNode, error) {
				return plan.BuildNode("test-node-empty").
					Endpoint("").
					Platform(sdk.PlatformAMD64).
					Build()
			},
			wantErr: sdk.ErrBuildNodeEndpointRequired,
		},
		{
			name: "whitespace-only endpoint",
			build: func(plan *sdk.Plan) (*sdk.BuildNode, error) {
				return plan.BuildNode("test-node-whitespace").
					Endpoint("   ").
					Platform(sdk.PlatformAMD64).
					Build()
			},
			wantErr: sdk.ErrBuildNodeEndpointRequired,
		},
		{
			name: "missing platform",
			build: func(plan *sdk.Plan) (*sdk.BuildNode, error) {
				return plan.BuildNode("test-node-no-platform").
					Endpoint("ssh://builder@192.168.1.100").
					Build()
			},
			wantErr: sdk.ErrBuildNodePlatformRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			plan := sdk.NewPlan("test-plan")
			node, err := tt.build(plan)

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

			if node == nil {
				t.Error("Build() returned nil node with nil error")
			}
		})
	}
}
