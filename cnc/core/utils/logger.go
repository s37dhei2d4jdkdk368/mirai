package utils

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	ColorGray  = "\x1b[90m"
	ColorGreen = "\x1b[32m"
	ColorCyan  = "\x1b[36m"
	ColorWhite = "\x1b[37m"
	ColorReset = "\x1b[0m"
)

func Log(level string, message string) {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		line = 0
	} else {
		file = filepath.Base(file)
	}

	timestamp := time.Now().Format("3:04PM")

	
	formattedMsg := colorizeMessage(message)

	levelColor := ColorCyan
	if level == "ERROR" {
		levelColor = "\x1b[31m"
	}

	fmt.Printf("%s%s %s%s %s> %s%s:%d %s> %s\n",
		ColorGray, timestamp,
		levelColor, level,
		ColorGray,
		ColorWhite, file, line,
		ColorGray,
		formattedMsg,
	)
}

func colorizeMessage(msg string) string {
	
	if strings.HasPrefix(msg, "Successfully") || strings.HasPrefix(msg, "Loaded") {
		
		return ColorGreen + msg + ColorReset
	}

	parts := strings.Split(msg, " ")
	for i, part := range parts {
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			
			
			val := kv[1]
			suffix := ""
			if strings.HasSuffix(val, ",") {
				val = val[:len(val)-1]
				suffix = ","
			}
			
			parts[i] = fmt.Sprintf("%s%s=%s%s%s%s", ColorGray, kv[0], ColorWhite, val, ColorGray, suffix)
		}
	}

	return ColorWhite + strings.Join(parts, " ") + ColorReset
}

func Infof(format string, a ...interface{}) {
	Log("INFO", fmt.Sprintf(format, a...))
}

func Errorf(format string, a ...interface{}) {
	Log("ERROR", fmt.Sprintf(format, a...))
}

func Successf(format string, a ...interface{}) {
	Log("SUCCESSFULLY", fmt.Sprintf(format, a...))
}
