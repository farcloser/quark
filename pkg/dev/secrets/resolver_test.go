package secrets_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/farcloser/quark/pkg/dev/secrets"
	"github.com/farcloser/quark/pkg/fault"
)

// mockBackend implements Backend for testing.
type mockBackend struct {
	scheme         string
	resolveFunc    func(ctx context.Context, path string, fields []string) (map[string]string, error)
	resolveDocFunc func(ctx context.Context, path string) ([]byte, error)
}

func (m *mockBackend) Scheme() string {
	return m.scheme
}

func (m *mockBackend) Resolve(ctx context.Context, path string, fields []string) (map[string]string, error) {
	if m.resolveFunc != nil {
		return m.resolveFunc(ctx, path, fields)
	}

	return nil, errors.New("not implemented")
}

func (m *mockBackend) ResolveDocument(ctx context.Context, path string) ([]byte, error) {
	if m.resolveDocFunc != nil {
		return m.resolveDocFunc(ctx, path)
	}

	return nil, errors.New("not implemented")
}

func TestResolver_Register(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}
	backend := &mockBackend{scheme: "test"}

	// Should not panic
	resolver.Register(backend)
}

func TestResolver_Resolve_Success(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}
	backend := &mockBackend{
		scheme: "mock",
		resolveFunc: func(_ context.Context, path string, fields []string) (map[string]string, error) {
			if path != "vault/item" {
				t.Errorf("path = %q, want %q", path, "vault/item")
			}

			if len(fields) != 2 || fields[0] != "username" || fields[1] != "password" {
				t.Errorf("fields = %v, want [username password]", fields)
			}

			return map[string]string{
				"username": "admin",
				"password": "secret",
			}, nil
		},
	}
	resolver.Register(backend)

	result, err := resolver.Resolve(context.Background(), "mock://vault/item", []string{"username", "password"})
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}

	if result["username"] != "admin" {
		t.Errorf("result[username] = %q, want %q", result["username"], "admin")
	}

	if result["password"] != "secret" {
		t.Errorf("result[password] = %q, want %q", result["password"], "secret")
	}
}

func TestResolver_Resolve_NoScheme(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}

	_, err := resolver.Resolve(context.Background(), "no-scheme-here", nil)
	if err == nil {
		t.Fatal("Resolve() should return error for URI without scheme")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want %v", err, fault.ErrInvalidArgument)
	}
}

func TestResolver_Resolve_UnknownScheme(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}

	_, err := resolver.Resolve(context.Background(), "unknown://path", nil)
	if err == nil {
		t.Fatal("Resolve() should return error for unknown scheme")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want %v", err, fault.ErrInvalidArgument)
	}
}

func TestResolver_ResolveDocument_Success(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}
	backend := &mockBackend{
		scheme: "file",
		resolveDocFunc: func(_ context.Context, path string) ([]byte, error) {
			if path != "path/to/secret.age" {
				t.Errorf("path = %q, want %q", path, "path/to/secret.age")
			}

			return []byte("decrypted content"), nil
		},
	}
	resolver.Register(backend)

	result, err := resolver.ResolveDocument(context.Background(), "file://path/to/secret.age")
	if err != nil {
		t.Fatalf("ResolveDocument() error = %v, want nil", err)
	}

	if string(result) != "decrypted content" {
		t.Errorf("result = %q, want %q", string(result), "decrypted content")
	}
}

func TestResolver_ResolveDocument_NoScheme(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}

	_, err := resolver.ResolveDocument(context.Background(), "no-scheme")
	if err == nil {
		t.Fatal("ResolveDocument() should return error for URI without scheme")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want %v", err, fault.ErrInvalidArgument)
	}
}

func TestResolver_ResolveDocument_UnknownScheme(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}

	_, err := resolver.ResolveDocument(context.Background(), "unknown://path")
	if err == nil {
		t.Fatal("ResolveDocument() should return error for unknown scheme")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("error = %v, want %v", err, fault.ErrInvalidArgument)
	}
}

func TestResolver_MultipleBackends(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}

	opBackend := &mockBackend{
		scheme: "op",
		resolveFunc: func(_ context.Context, _ string, _ []string) (map[string]string, error) {
			return map[string]string{"source": "1password"}, nil
		},
	}

	vaultBackend := &mockBackend{
		scheme: "vault",
		resolveFunc: func(_ context.Context, _ string, _ []string) (map[string]string, error) {
			return map[string]string{"source": "hashicorp"}, nil
		},
	}

	resolver.Register(opBackend)
	resolver.Register(vaultBackend)

	// Test op backend
	result1, err := resolver.Resolve(context.Background(), "op://vault/item", nil)
	if err != nil {
		t.Fatalf("Resolve(op://) error = %v", err)
	}

	if result1["source"] != "1password" {
		t.Errorf("op:// source = %q, want %q", result1["source"], "1password")
	}

	// Test vault backend
	result2, err := resolver.Resolve(context.Background(), "vault://secret/data", nil)
	if err != nil {
		t.Fatalf("Resolve(vault://) error = %v", err)
	}

	if result2["source"] != "hashicorp" {
		t.Errorf("vault:// source = %q, want %q", result2["source"], "hashicorp")
	}
}

func TestResolver_BackendOverwrite(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}

	backend1 := &mockBackend{
		scheme: "test",
		resolveFunc: func(_ context.Context, _ string, _ []string) (map[string]string, error) {
			return map[string]string{"version": "1"}, nil
		},
	}

	backend2 := &mockBackend{
		scheme: "test",
		resolveFunc: func(_ context.Context, _ string, _ []string) (map[string]string, error) {
			return map[string]string{"version": "2"}, nil
		},
	}

	resolver.Register(backend1)
	resolver.Register(backend2)

	result, err := resolver.Resolve(context.Background(), "test://path", nil)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	// Second registration should overwrite first
	if result["version"] != "2" {
		t.Errorf("version = %q, want %q", result["version"], "2")
	}
}

func TestResolver_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}
	backend := &mockBackend{
		scheme: "concurrent",
		resolveFunc: func(_ context.Context, _ string, _ []string) (map[string]string, error) {
			return map[string]string{"ok": "true"}, nil
		},
	}
	resolver.Register(backend)

	const goroutines = 50

	var wg sync.WaitGroup

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			_, err := resolver.Resolve(context.Background(), "concurrent://path", nil)
			if err != nil {
				t.Errorf("Resolve() error = %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestResolver_ConcurrentRegisterAndResolve(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}

	const goroutines = 20

	var wg sync.WaitGroup

	wg.Add(goroutines * 2)

	// Concurrent registrations
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()

			backend := &mockBackend{
				scheme: "scheme",
				resolveFunc: func(_ context.Context, _ string, _ []string) (map[string]string, error) {
					return map[string]string{"idx": string(rune('0' + idx))}, nil
				},
			}
			resolver.Register(backend)
		}(i)
	}

	// Concurrent resolutions (some may fail if backend not yet registered)
	for range goroutines {
		go func() {
			defer wg.Done()

			// This may succeed or fail depending on timing - we just check no race
			_, _ = resolver.Resolve(context.Background(), "scheme://path", nil)
		}()
	}

	wg.Wait()
}

func TestResolver_BackendError(t *testing.T) {
	t.Parallel()

	resolver := &secrets.Resolver{}
	backendErr := errors.New("backend failure")
	backend := &mockBackend{
		scheme: "failing",
		resolveFunc: func(_ context.Context, _ string, _ []string) (map[string]string, error) {
			return nil, backendErr
		},
	}
	resolver.Register(backend)

	_, err := resolver.Resolve(context.Background(), "failing://path", nil)
	if err == nil {
		t.Fatal("Resolve() should return backend error")
	}

	if !errors.Is(err, backendErr) {
		t.Errorf("error = %v, want %v", err, backendErr)
	}
}

func TestResolver_URIParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		uri        string
		wantScheme string
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "simple",
			uri:        "op://vault/item",
			wantScheme: "op",
			wantPath:   "vault/item",
		},
		{
			name:       "with slashes in path",
			uri:        "file://path/to/nested/secret.age",
			wantScheme: "file",
			wantPath:   "path/to/nested/secret.age",
		},
		{
			name:       "empty path",
			uri:        "scheme://",
			wantScheme: "scheme",
			wantPath:   "",
		},
		{
			name:    "no scheme separator",
			uri:     "noscheme",
			wantErr: true,
		},
		{
			name:    "single colon",
			uri:     "scheme:path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resolver := &secrets.Resolver{}

			if !tt.wantErr {
				backend := &mockBackend{
					scheme: tt.wantScheme,
					resolveFunc: func(_ context.Context, path string, _ []string) (map[string]string, error) {
						if path != tt.wantPath {
							t.Errorf("path = %q, want %q", path, tt.wantPath)
						}

						return map[string]string{}, nil
					},
				}
				resolver.Register(backend)
			}

			_, err := resolver.Resolve(context.Background(), tt.uri, nil)

			if tt.wantErr {
				if err == nil {
					t.Error("Resolve() should return error")
				}
			} else {
				if err != nil {
					t.Errorf("Resolve() error = %v, want nil", err)
				}
			}
		})
	}
}
