// Package dev provides full-featured generic systems built on top of primitives from core.
// While they are not generic primitives (but instead complete implementations meant for a specific task), they
// are not specific to quark, and could either be split out in individual libraries, or be used by others outside of
// quark, to build higher-level systems (like Hadron).
// Specifically includes tools installation helpers, content-addressable stores, a DAG implementation, full featured
// ssh client, etc.
// None of this should be exposed directly to quark *users*.
package dev
