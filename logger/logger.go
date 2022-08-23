package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const LogFilePath = "/tmp/dis-sdns.log"

var sugar *zap.SugaredLogger

func Initialize(debug bool) error {
	var logger *zap.Logger
	var err error
	if debug {
		var cfg = zap.NewDevelopmentConfig()
		cfg.Encoding = "console"
		cfg.OutputPaths = []string{
			"stdout",
			LogFilePath,
		}

		logger, err = cfg.Build()
		if err != nil {
			return err
		}
		defer logger.Sync()
	} else {
		w := zapcore.AddSync(&lumberjack.Logger{
			Filename:   LogFilePath,
			MaxSize:    500, // megabytes
			MaxBackups: 3,
			MaxAge:     2, // days
		})
		core := zapcore.NewCore(
			zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
			w,
			zap.InfoLevel,
		)
		logger = zap.New(core)
	}
	sugar = logger.Sugar()
	return nil
}

func Get() *zap.SugaredLogger {
	return sugar
}
