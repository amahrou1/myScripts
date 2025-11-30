package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
	logFile     *os.File
)

// Init initializes the logging system
func Init(outputDir string, debug bool) error {
	// Create logs directory
	logsDir := filepath.Join(outputDir, "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}

	// Create log file with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logPath := filepath.Join(logsDir, fmt.Sprintf("recon_%s.log", timestamp))

	var err error
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}

	// Initialize loggers
	infoLogger = log.New(logFile, "[INFO] ", log.Ldate|log.Ltime)
	errorLogger = log.New(logFile, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile)
	debugLogger = log.New(logFile, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile)

	Info("Logging initialized at %s", logPath)
	return nil
}

// Close closes the log file
func Close() {
	if logFile != nil {
		logFile.Close()
	}
}

// Info logs an info message
func Info(format string, v ...interface{}) {
	if infoLogger != nil {
		infoLogger.Printf(format, v...)
	}
}

// Error logs an error message
func Error(format string, v ...interface{}) {
	if errorLogger != nil {
		errorLogger.Printf(format, v...)
	}
}

// Debug logs a debug message
func Debug(format string, v ...interface{}) {
	if debugLogger != nil {
		debugLogger.Printf(format, v...)
	}
}

// Fatal logs a fatal error and exits
func Fatal(format string, v ...interface{}) {
	if errorLogger != nil {
		errorLogger.Printf("[FATAL] "+format, v...)
	}
	log.Fatalf(format, v...)
}
