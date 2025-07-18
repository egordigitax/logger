package logger

import (
	"fmt"
	zlogsentry "github.com/egordigitax/zerolog-sentry"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
	"io"
	"os"
)

const logTimeFormat = "2006-01-02T15:04:05"

type (
	Config struct {
		Level     string `yaml:"level"`
		JSON      bool   `yaml:"json"`
		SentryDSN string `yaml:"sentryDSN"`
	}

	Environment string
	Version     string
)

var (
	defaultLogger  *zerolog.Logger
	disabledLogger *zerolog.Logger
)

func DefaultConsoleLogger() *zerolog.Logger {
	if defaultLogger != nil {
		return defaultLogger
	}

	l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: logTimeFormat}).With().Timestamp().Logger()
	defaultLogger = &l
	return defaultLogger
}

func DisabledLogger() *zerolog.Logger {
	if disabledLogger != nil {
		return disabledLogger
	}

	l := zerolog.Nop()
	disabledLogger = &l
	return disabledLogger
}

func WithCliVersionLogger(logger *zerolog.Logger, c *cli.Context) *zerolog.Logger {
	l := logger.With().
		Str("version", c.App.Version).
		Logger()

	return &l
}

func ProvideLogger(cfg Config, env Environment, version Version) (*zerolog.Logger, error) {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("provider: problem while parsing log level: %w", err)
	}

	sentryOpts := []zlogsentry.WriterOption{
		zlogsentry.WithEnvironment(string(env)),
		zlogsentry.WithRelease(string(version)),
	}

	levels := []zerolog.Level{
		zerolog.PanicLevel,
		zerolog.FatalLevel,
		zerolog.ErrorLevel,
		zerolog.WarnLevel,
	}
	if level == zerolog.DebugLevel {
		levels = append(levels, zerolog.DebugLevel)
		sentryOpts = append(sentryOpts, zlogsentry.WithDebug())
	}
	sentryOpts = append(sentryOpts, zlogsentry.WithLevels(levels...))

	writer, err := logWriter(cfg, sentryOpts)
	if err != nil {
		return nil, err
	}

	logger := zerolog.New(writer).Level(level).With().Timestamp().Logger()
	logger.Info().Str("version", string(version)).Msg("logger initialized")

	return &logger, nil
}

func ProvideLogVersion(cli *cli.Context) Version {
	return Version(cli.App.Version)
}

func logWriter(cfg Config, sentryOpts []zlogsentry.WriterOption) (io.Writer, error) {
	var writer io.Writer

	if cfg.JSON {
		writer = os.Stdout
	} else {
		writer = zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) { w.TimeFormat = logTimeFormat })
	}

	if cfg.SentryDSN != "" {
		sentryWriter, err := zlogsentry.New(cfg.SentryDSN, sentryOpts...)
		if err != nil {
			return nil, fmt.Errorf("log writer: can't initialize zlogsentry: %w", err)
		}
		return io.MultiWriter(writer, sentryWriter), nil
	}

	return writer, nil
}
