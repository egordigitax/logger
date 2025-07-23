package logger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"gitlab.findmykids.org/fmk-pkg/crypto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"strconv"
	"strings"
	"time"
)

const (
	FingerprintKey     = "fingerprint"
	InfraFingerprint   = "infra"
	ContextFingerprint = "context"
)

type UserIDGetter func(token string) string
type LogLevelSpecifier func(logger *zerolog.Logger, msg string, err error) (*zerolog.Event, string, error)
type ApiErrorClassifier func(err error) (error, bool)

func FiberMiddleware(
	baseLogger *zerolog.Logger,
	userIdGetter UserIDGetter,
	logLevelSpecifier LogLevelSpecifier,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		enriched := baseLogger.With().
			Str("http.method", c.Method()).
			Str("http.path", c.Path()).
			Str("http.query", string(c.Request().URI().QueryString())).
			Str("http.ip", c.IP()).
			Str("http.user_agent", c.Get("User-Agent"))

		c.Context().QueryArgs().VisitAll(func(k, v []byte) {
			if string(k) == "u" {
				userId := userIdGetter(string(v))
				enriched = enriched.Str("user_id", userId)
			}
			enriched = enriched.Str(string(k), string(v))
		})

		enrichedLogger := enriched.Logger()

		c.Locals("logger", &enrichedLogger)

		err := c.Next()

		log, msg, _ := logLevelSpecifier(
			&enrichedLogger,
			fmt.Sprintf("%s handle http request", c.Path()),
			err,
		)

		event := log.Str("body", string(c.Request().Body())).
			Str("response", string(c.Response().Body())).
			Int("status", c.Response().StatusCode()).
			Dur("resp_time", time.Since(start))

		event.Msg(msg)

		return err
	}
}
func GRPCInterceptor(
	logger *zerolog.Logger,
	logLevelSpecifier LogLevelSpecifier,
) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		resp, err := handler(ctx, req)

		if err == nil {
			return resp, nil
		}

		tryGetUserId, ok := extractUserIDViaJSON(req)
		if !ok {
			tryGetUserId = "unknown"
		}

		log, msg, _ := logLevelSpecifier(
			logger,
			fmt.Sprintf("%s handle grpc request", info.FullMethod),
			err,
		)

		event := log.Str("method", info.FullMethod).
			Str("user_id", tryGetUserId).
			Interface("request", req)

		event.Msg(msg)

		return resp, err
	}
}

func extractUserIDViaJSON(req interface{}) (string, bool) {
	var jsonBytes []byte
	var err error

	if msg, ok := req.(proto.Message); ok {
		jsonStr := protojson.Format(msg)
		jsonBytes = []byte(jsonStr)
	} else {
		jsonBytes, err = json.Marshal(req)
		if err != nil {
			return "", false
		}
	}

	var data map[string]any
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return "", false
	}

	for _, key := range []string{"user_id", "userId", "id"} {
		if val, ok := data[key]; ok {
			switch v := val.(type) {
			case string:
				return v, true
			case float64:
				return strconv.FormatInt(int64(v), 10), true
			}
		}
	}
	return "", false
}

type SpecifierConfig struct {
	ApiErrorsGetterFunc ApiErrorClassifier
	ShouldLogApiErrors  bool

	ContextErrorsKeywords  []string
	ShouldLogContextErrors bool

	InfraErrorsKeywords  []string
	ShouldLogInfraErrors bool
}

func DefaultLogLevelSpecifier(
	config *SpecifierConfig,
) func(
	logger *zerolog.Logger,
	msg string,
	err error,
) (*zerolog.Event, string, error) {
	return func(
		logger *zerolog.Logger,
		msg string,
		err error,
	) (*zerolog.Event, string, error) {
		if err == nil {
			return logger.Info().Err(err), msg, nil
		}

		if config.ShouldLogContextErrors {
			for _, keyword := range config.ContextErrorsKeywords {
				if err != nil && strings.Contains(err.Error(), keyword) {
					return logger.Warn().Str(FingerprintKey, ContextFingerprint), "context errors", err
				}
			}
		}

		if config.ShouldLogInfraErrors {
			for _, keyword := range config.InfraErrorsKeywords {
				if err != nil && strings.Contains(err.Error(), keyword) {
					return logger.Warn().Str(FingerprintKey, InfraFingerprint), "infra problems", err
				}
			}
		}

		var fiberErr *fiber.Error
		if errors.As(err, &fiberErr) && fiberErr.Code == fiber.StatusNotFound {
			return logger.Info().Err(err), msg, fiberErr
		}

		if apiErr, ok := config.ApiErrorsGetterFunc(err); ok {
			if config.ShouldLogApiErrors {
				return logger.Warn().Err(err), msg, apiErr
			}
			return logger.Info().Err(err), msg, nil
		}

		return logger.Error().Err(err), msg, errors.New("internal server error")
	}
}

func DefaultUserIDGetter(conf *crypto.Config) UserIDGetter {
	return func(token string) string {
		userId, _ := crypto.GetIDByToken(token, conf)
		return strconv.FormatUint(userId, 10)
	}
}

func DefaultContextKeywords() []string {
	return []string{
		"deadline exceeded",
		"context canceled",
	}
}

func DefaultCombineInfraErrors() []string {
	return []string{
		"connection failure",
		"connection refused",
		"dial tcp",
		"upstream connect",
	}
}
