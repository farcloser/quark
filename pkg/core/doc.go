// Package core provides low-level primitives, that could be part of a generic core golang library.
// They are not specific to quark, and they do not provide high-level systems dedicated to a specific task.
// This typically includes cryptography primitives, default network transport, safe filesystem operations, etc.
// None of this should be exposed nor used by quark *users*, with the possible exception of `fault` that contain
// typed errors used across the codebase.
package core
