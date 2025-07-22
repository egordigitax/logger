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

type UserIDGetter func(token string) string
type LogLevelSpecifier func(logger *zerolog.Logger, err error) (*zerolog.Event, error)
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

		log, _ := logLevelSpecifier(&enrichedLogger, err)

		event := log.Str("body", string(c.Request().Body())).
			Str("response", string(c.Response().Body())).
			Int("status", c.Response().StatusCode()).
			Dur("resp_time", time.Since(start))

		SendEvent(event, err, fmt.Sprintf("%s handle http request", c.Path()))

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
		if err != nil {

			tryGetUserId, ok := extractUserIDViaJSON(req)
			if !ok {
				tryGetUserId = "unknown"
			}

			log, _ := logLevelSpecifier(logger, err)

			event := log.Str("method", info.FullMethod).
				Str("user_id", tryGetUserId).
				Interface("request", req).
				Err(err)

			SendEvent(event, err, fmt.Sprintf("%s handle grpc request", info.FullMethod))
		}
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

func DefaultLogLevelSpecifier(
	apiErrorClassifier ApiErrorClassifier,
	excludeErrorKeywords []string,
	shouldLogApiErrors bool,
) func(
	logger *zerolog.Logger,
	err error,
) (*zerolog.Event, error) {
	return func(
		logger *zerolog.Logger,
		err error,
	) (*zerolog.Event, error) {
		if err == nil {
			return logger.Info(), nil
		}

		for _, keyword := range excludeErrorKeywords {
			if strings.Contains(err.Error(), keyword) {
				return logger.Info(), nil
			}
		}

		var fiberErr *fiber.Error
		if errors.As(err, &fiberErr) && fiberErr.Code == fiber.StatusNotFound {
			return logger.Info().Err(err), fiberErr
		}

		if apiErr, ok := apiErrorClassifier(err); ok {
			if shouldLogApiErrors {
				return logger.Warn().Err(err), apiErr
			}
			return logger.Info().Err(err), nil
		}

		return logger.Error().Err(err), errors.New("internal server error")
	}
}

func SendEvent(event *zerolog.Event, err error, msg string) {
	for _, keyword := range DefaultCombineInfraErrors() {
		if strings.Contains(err.Error(), keyword) {
			event.Str("fingerprint", "infra").Msg("infra problems")
			return
		}
	}
	event.Msg(msg)
	return
}

func DefaultUserIDGetter(conf *crypto.Config) UserIDGetter {
	return func(token string) string {
		userId, _ := crypto.GetIDByToken(token, conf)
		return strconv.FormatUint(userId, 10)
	}
}

func DefaultExcludeKeywords() []string {
	return []string{
		"deadline exceeded",
		"context canceled",
	}
}

func DefaultCombineInfraErrors() []string {
	return []string{
		"connection failure",
		"connection refused",
	}
}
