# logger

Либа предназначена для облегчения работы с zerolog и обеспечивает интеграцию с sentry

# usage in wire

```go
package main

import (
	"github.com/google/wire"
	"gitlab.findmykids.org/fmk-pkg/logger"
)

type Config struct {
	Environment string
	Log         logger.Config
}

var CliSet = wire.NewSet(
	logger.ProvideLogVersion,
	ProvideLogEnvironment,
	ProvideLogConfig,
	logger.ProvideLogger,
)

func ProvideLogEnvironment(conf *Config) logger.Environment {
	return logger.Environment(conf.Environment)
}

func ProvideLogConfig(conf *Config) logger.Config {
	return conf.Log
}

```