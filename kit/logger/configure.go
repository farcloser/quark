package logger

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	slogzerolog "github.com/samber/slog-zerolog/v2"
)

// SetDefaults configures a global zerolog logger with sensible defaults.
// It uses a console writer with RFC3339 timestamps for human-readable output.
// If a log level is provided, it sets that level. Otherwise, it reads from the LOG_LEVEL
// environment variable (defaults to "info" if not set or invalid).
func SetDefaults(ctx context.Context, level ...zerolog.Level) {
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	log.Logger.WithContext(ctx)

	if len(level) > 0 {
		// Explicit level provided
		zerolog.SetGlobalLevel(level[0])
	} else {
		// Read from LOG_LEVEL environment variable
		logLevel := os.Getenv("LOG_LEVEL")
		if logLevel == "" {
			logLevel = "info"
		}

		parsedLevel, err := zerolog.ParseLevel(logLevel)
		if err != nil {
			// Invalid level, default to info
			parsedLevel = zerolog.InfoLevel

			log.Warn().Str("LOG_LEVEL", logLevel).Msg("Invalid log level, defaulting to info")
		}

		zerolog.SetGlobalLevel(parsedLevel)
	}

	slog.SetDefault(slog.New(slogzerolog.Option{Level: slog.LevelDebug, Logger: &log.Logger}.NewZerologHandler()))
}
