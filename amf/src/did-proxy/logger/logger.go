/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

package logger

import (
	"fmt"
	"log"
	"os"
	"time"
)

// LogLevel represents logging levels
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
)

// Logger provides OAI-style logging functionality
type Logger struct {
	name   string
	level  LogLevel
	logger *log.Logger
}

// NewLogger creates a new logger instance
func NewLogger(name string) *Logger {
	return &Logger{
		name:   name,
		level:  DEBUG,
		logger: log.New(os.Stdout, "", 0),
	}
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level string) {
	switch level {
	case "debug":
		l.level = DEBUG
	case "info":
		l.level = INFO
	case "warn":
		l.level = WARN
	case "error":
		l.level = ERROR
	default:
		l.level = INFO
	}
}

// formatMessage formats a log message in OAI style
func (l *Logger) formatMessage(level, format string, args ...interface{}) string {
	timestamp := time.Now().Format("2006-01-02T15:04:05.000000")
	msg := fmt.Sprintf(format, args...)
	return fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, l.name, level, msg)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level <= DEBUG {
		l.logger.Println(l.formatMessage("debug", format, args...))
	}
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level <= INFO {
		l.logger.Println(l.formatMessage("info ", format, args...))
	}
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level <= WARN {
		l.logger.Println(l.formatMessage("warn ", format, args...))
	}
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level <= ERROR {
		l.logger.Println(l.formatMessage("error", format, args...))
	}
}

// Startup logs a startup message (special OAI style)
func (l *Logger) Startup(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.logger.Printf("[%s] [%s] [startup] %s\n",
		time.Now().Format("2006-01-02T15:04:05.000000"), l.name, msg)
}
