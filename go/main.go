// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// filescanner — async USB Spectra Detect scanner (Go port of filescanner.py).
//
// submit → task_url → ScanDB (sqlite) → result pollers → NDJSON + reports.
// Configuration is INI-driven; see config.ini.template for every section/key.
//
// Usage:
//
//	filescanner --init-config config.ini   # write default config
//	filescanner --config config.ini        # run a scan
package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed config.ini.template
var configTemplate []byte

func defaultDesktopDir() string {
	home, _ := os.UserHomeDir()
	// Windows OneDrive/known-folder redirection: Go can't read the registry
	// without a dep; USERPROFILE\Desktop is right on modern default installs.
	return filepath.Join(home, "Desktop")
}

func resolveOutputDir(a *Args, log *Logger) string {
	out := a.OutputDir
	if out == "" {
		out = filepath.Join(defaultDesktopDir(), "Spectra")
	} else if strings.HasPrefix(out, "~") {
		home, _ := os.UserHomeDir()
		out = filepath.Join(home, strings.TrimPrefix(out, "~"))
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Error("Could not create output directory %s: %v", out, err)
		cwd, _ := os.Getwd()
		log.Warn("Falling back to current working directory: %s", cwd)
		out = cwd
	}
	return out
}

func main() {
	configPath := flag.String("config", "config.ini", "Path to config.ini")
	initConfig := flag.String("init-config", "",
		"Write a default config.ini to PATH and exit")
	flag.Parse()

	if *initConfig != "" {
		if err := os.WriteFile(*initConfig, configTemplate, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "init-config failed:", err)
			os.Exit(1)
		}
		fmt.Println("Wrote", *initConfig)
		return
	}

	args, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot load config %s: %v\n", *configPath, err)
		os.Exit(2)
	}

	// Console-only logger until output dir resolves.
	provisional := newLogger(args.Verbose, "", 0, 0)
	outputDir := resolveOutputDir(args, provisional)
	// Per-run artifact folder keeps each scan's log/reports/ndjson separate.
	// scan_state.db stays at outputDir so resume works across runs.
	runDir := filepath.Join(outputDir, "run_"+time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		provisional.Error("Could not create run dir %s: %v", runDir, err)
		runDir = outputDir
	}
	log := newLogger(args.Verbose, filepath.Join(runDir, LogFilename),
		args.LogMaxMB, args.LogBackups)
	defer log.Close()

	if msg := normalizeArgs(args, log); msg != "" {
		log.Error("%s", msg)
		os.Exit(2)
	}
	include := determineExtensions(args)

	log.Info("========================================================================")
	log.Info("USB Spectra Detect Scanner v%s (Go)", ScriptVersion)
	log.Info("========================================================================")
	log.Info("Configuration:")
	log.Info("  Drive:                %s", args.Drive)
	log.Info("  Spectra Detect Host:  %s", args.Host)
	log.Info("  Workers:              %d", args.UploadWorkers)
	log.Info("  Result Pollers:       %d", args.ResultPollers)
	log.Info("  Analysis Depth:       %s", args.AnalysisDepth)
	log.Info("  Resume:               %s", onOff(args.Resume))
	log.Info("  Detect File Type:     %s", onOff(args.DetectFileType))
	log.Info("  Extract Strings:      %s", onOff(args.ExtractStrings))
	log.Info("  Extract IOCs:         %s", onOff(args.ExtractIOCs))
	log.Info("  File-type Filter:     %s", joinOr(sortedKeys(args.FileTypesSet), "none"))
	log.Info("  Quarantine:           %s (on: %s)", args.QuarantineAction,
		joinOr(sortedKeys(args.QuarantineOn), "none"))
	log.Info("  Alert On:             %s", joinOr(sortedKeys(args.AlertOn), "none"))
	log.Info("  Report Formats:       %s", strings.Join(sortedKeys(args.ReportFormats), ","))
	if args.NoVerifySSL {
		log.Info("  SSL Verification:     Disabled")
	} else {
		log.Info("  SSL Verification:     Enabled")
	}
	log.Info("  Output Directory:     %s", outputDir)
	log.Info("  Run Directory:        %s", runDir)
	if include != nil {
		log.Info("  Extension Filter:     %d types", len(include))
	} else {
		log.Info("  Extension Filter:     NONE (all files)")
	}
	log.Info("------------------------------------------------------------------------")

	// SIGINT (Python KeyboardInterrupt): see interruptCtl.watch.
	ic := newInterruptCtl()
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go ic.watch(sigCh, log)

	output := runScan(args, include, outputDir, runDir, log, ic)

	writeReports(output, runDir, args.Output, args.ReportFormats, log)
	ic.markReportsDone()

	summary, _ := output["summary"].(map[string]any)
	log.Info("------------------------------------------------------------------------")
	log.Info("SCAN COMPLETE")
	log.Info("  Total files matched:     %v", summary["total_files_matched_filter"])
	log.Info("  Files processed:         %v", summary["files_processed"])
	log.Info("  Completed/cached:        %v", summary["files_completed_successfully"])
	log.Info("  Uploads submitted:       %v", summary["uploads_submitted"])
	log.Info("  Cached hits:             %v", summary["cached_hits"])
	log.Info("  Skipped (file-type):     %v", summary["skipped_by_filetype"])
	log.Info("  Malicious:               %v", summary["malicious"])
	log.Info("  Suspicious:              %v", summary["suspicious"])
	log.Info("  Quarantined:             %v", summary["quarantined"])
	log.Info("  Alerts raised:           %v", summary["alerts"])
	log.Info("  Errors:                  %v", summary["files_with_errors"])
	log.Info("========================================================================")

	if n, _ := summary["files_with_errors"].(int); n > 0 {
		os.Exit(1)
	}
}

// interruptGrace bounds how long a first Ctrl-C waits for in-flight
// uploads/polls before reporting from DB state (Python abandons its daemon
// worker threads outright).
const interruptGrace = 2 * time.Second

// interruptCtl mirrors Python's KeyboardInterrupt handling:
//   - Ctrl-C before the pipeline runs (readiness wait, prompts): exit 130,
//     no reports (Python's KeyboardInterrupt is uncaught there).
//   - First Ctrl-C while it runs: close stop — walking/uploading new files
//     and the pollers halt, then main writes reports from the DB and exits
//     with the normal code (1 if files_with_errors else 0), like Python.
//   - Second Ctrl-C: exit 130, after reports finish or forceWait elapses.
type interruptCtl struct {
	stop        chan struct{}
	stopOnce    sync.Once
	live        atomic.Bool // pipeline running: Ctrl-C stops it gracefully
	reportsDone chan struct{}
	reportsOnce sync.Once
	forceWait   time.Duration
	exit        func(int)
}

func newInterruptCtl() *interruptCtl {
	return &interruptCtl{stop: make(chan struct{}),
		reportsDone: make(chan struct{}), forceWait: 10 * time.Second,
		exit: os.Exit}
}

func (ic *interruptCtl) Stop() { ic.stopOnce.Do(func() { close(ic.stop) }) }

func (ic *interruptCtl) markReportsDone() {
	ic.reportsOnce.Do(func() { close(ic.reportsDone) })
}

func (ic *interruptCtl) watch(sigCh <-chan os.Signal, log *Logger) {
	<-sigCh
	if !ic.live.Load() {
		log.Warn("Interrupted.")
		ic.exit(130)
		return
	}
	ic.Stop() // runScan logs "Interrupted - writing reports ..."
	<-sigCh
	log.Warn("Force quit - waiting up to %s for reports.", ic.forceWait)
	select {
	case <-ic.reportsDone:
	case <-time.After(ic.forceWait):
	}
	ic.exit(130)
}

// waitPipeline blocks until done closes (normal end, returns false) or stop
// closes (returns true after waiting at most grace for in-flight work).
func waitPipeline(done, stop <-chan struct{}, grace time.Duration,
	log *Logger) bool {
	select {
	case <-done:
		return false
	case <-stop:
	}
	log.Warn("Interrupted - writing reports from collected state.")
	select {
	case <-done:
	case <-time.After(grace):
		log.Warn("In-flight uploads/polls abandoned after %s; their rows "+
			"stay pending for the next (resume) run.", grace)
	}
	return true
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
func joinOr(ss []string, def string) string {
	if len(ss) == 0 {
		return def
	}
	return strings.Join(ss, ", ")
}
