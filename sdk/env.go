package sdk

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// LoadEnv loads environment variables from the specified .env file.
// Values in the .env file will override existing environment variables.
// Returns an error if the file doesn't exist or cannot be loaded.
func LoadEnv(path string) error {
	if err := godotenv.Overload(path); err != nil {
		return fmt.Errorf("failed to load .env file %q: %w", path, err)
	}

	return nil
}

// GetEnv retrieves an environment variable value.
// Returns an error if the variable does not exist.
// Empty values (FOO="") are allowed and will not cause an error.
func GetEnv(key string) (string, error) {
	value, exists := os.LookupEnv(key)
	if !exists {
		return "", fmt.Errorf("%w: %q", ErrEnvVarNotSet, key)
	}

	return value, nil
}

// GetEnvDefault retrieves an environment variable value with a default fallback.
// If the variable does not exist, it returns the default value.
// Empty values (FOO="") are NOT replaced with the default - only missing variables use the default.
func GetEnvDefault(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}

	return value
}
