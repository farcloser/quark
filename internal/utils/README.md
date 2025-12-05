# Package utils

## Purpose

Provides cross-platform utility functions for runtime directory management and other common operations.

## Functionality

- **Runtime directory** - Get platform-appropriate directory for sockets and ephemeral files

## Public API

```go
// RuntimeDir returns the user's runtime directory for storing sockets and other
// ephemeral runtime files.
//
// On Linux, this returns $XDG_RUNTIME_DIR (typically /run/user/<uid>).
// On macOS, this returns ~/.quark/run.
// On other platforms, this falls back to os.TempDir().
//
// The returned path is not guaranteed to exist; callers should create it as needed.
func RuntimeDir() string
```

## Design

- **XDG compliance**: Follows XDG Base Directory Specification on Linux
- **macOS handling**: Uses user-specific directory under home (~/.quark/run)
- **Fallback behavior**: Falls back to system temp directory on unsupported platforms
- **No auto-creation**: Returns path only; caller responsible for creating directory

## Platform Behavior

| Platform | Environment Variable | Default Path |
|----------|---------------------|--------------|
| Linux | `$XDG_RUNTIME_DIR` | `/run/user/<uid>` or `os.TempDir()` |
| macOS | - | `~/.quark/run` |
| Windows/Other | - | `os.TempDir()` |

## Dependencies

- External: None
- Internal: None (standalone module)

## Usage Notes

- Callers should use `os.MkdirAll()` to create the directory if needed
- Directory is suitable for Unix sockets, PID files, and other runtime state
- Content in runtime directories is typically not preserved across reboots
