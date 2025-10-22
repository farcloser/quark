package sdk

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

// LoadEnv loads environment variables from the specified .env file.
// Values in the .env file will override existing environment variables.
// If the file doesn't exist or cannot be loaded, it logs a fatal error and exits.
func LoadEnv(path string) error {
	if err := godotenv.Overload(path); err != nil {
		log.Fatal().Err(err).Str("path", path).Msg("Failed to load .env file")
	}

	return nil
}

// GetEnv retrieves an environment variable value.
// If the variable does not exist, it logs a fatal error and exits.
// Empty values (FOO="") are allowed and will not cause an error.
func GetEnv(key string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		log.Fatal().Str("key", key).Msg("Required environment variable not set")
	}

	return value
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
