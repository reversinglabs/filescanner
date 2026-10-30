// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build !windows

// eventlog_other.go — no-op stub so non-Windows builds compile; the
// channel is only meaningful on Windows anyway.
package main

func setupEventLog(log *Logger) func(cls string, msg string) {
	log.Warn("alert_eventlog is only supported on Windows builds; " +
		"disabling that channel.")
	return nil
}
