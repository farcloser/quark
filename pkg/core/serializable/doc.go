// Package serializable provides configuration serialization for flat key-value formats.
//
// This package is designed for configuration formats like APT config files, command-line
// arguments, and similar flat structures. These formats do not support nested structures,
// arrays, or complex types - only scalar values (strings, booleans, integers, floats).
//
// Supported types: string, bool, int/int8/int16/int32/int64, uint/uint8/uint16/uint32/uint64,
// float32, float64.
//
// Unsupported types (slices, maps, nested structs, pointers) produce empty string values
// without error, allowing partial serialization of mixed-type structs.
package serializable
