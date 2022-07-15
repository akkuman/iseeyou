package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

var (
	log = logrus.New()
)

// TODO: error级别日志增加钉钉机器人通知
func init() {
	log.Formatter = new(logrus.TextFormatter)
	log.Formatter.(*logrus.TextFormatter).DisableColors = true    // remove colors
	log.Level = logrus.InfoLevel
	log.Out = os.Stdout
}

func GetLogger() *logrus.Logger {
	return log
}

func Debugf(format string, args ...interface{}) {
	log.Debugf(format, args...)
}

func Infof(format string, args ...interface{}) {
	log.Infof(format, args...)
}

func Warnf(format string, args ...interface{}) {
	log.Warnf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	log.Fatalf(format, args...)
}
