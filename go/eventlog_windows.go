// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build windows

// eventlog_windows.go — Windows Event Log alert channel (parity with the
// Python pywin32 path). Event source registration needs admin once;
// eventlog.InstallAsEventCreate uses EventCreate's message file so no
// custom message DLL is required.
package main

import (
	"golang.org/x/sys/windows/svc/eventlog"
)

// setupEventLog returns a sender func or nil (channel disabled) if the
// source can't be opened/registered.
func setupEventLog(log *Logger) func(cls string, msg string) {
	const src = "SpectraDetectScanner"
	el, err := eventlog.Open(src)
	if err != nil {
		// First run needs registration (admin) — EventCreate message file
		// gives us "generic" events rather than failing outright.
		if ierr := eventlog.InstallAsEventCreate(src,
			eventlog.Error|eventlog.Warning|eventlog.Info); ierr != nil {
			log.Warn("Event Log source registration failed (needs admin): %v",
				ierr)
			return nil
		}
		if el, err = eventlog.Open(src); err != nil {
			log.Warn("Event Log open failed after registration: %v", err)
			return nil
		}
	}
	return func(cls, msg string) {
		if cls == "malicious" {
			el.Error(1, msg)
		} else {
			el.Warning(1, msg)
		}
	}
}
