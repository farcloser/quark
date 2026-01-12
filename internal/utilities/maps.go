package utilities

import "maps"

// MergeMaps merges two string maps, with override values taking precedence over base values.
// Returns a new map containing all keys from both maps.
func MergeMaps(base, override map[string]string) map[string]string {
	if base == nil && override == nil {
		return nil
	}

	result := make(map[string]string, len(base)+len(override))

	maps.Copy(result, base)

	maps.Copy(result, override)

	return result
}
