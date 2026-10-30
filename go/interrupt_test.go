// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// First Ctrl-C (Stop closed) mid-run: walking/uploading stops, pollers exit
// promptly even though reports never arrive, and nothing is marked failed
// (Python leaves interrupted rows pending/submitted, so the exit code is
// still derived from real errors only).
func TestStopHaltsPipelinePromptly(t *testing.T) {
	a := integrationArgs()
	a.UploadWorkers = 1
	ctx := integrationCtx(t, a)
	ctx.reportWait = time.Hour // without Stop the poller would wait forever
	stop := make(chan struct{})
	ctx.Stop = stop
	db := newIntegrationDB(t)
	defer db.Close()
	go func() {
		for db.InFlight() == 0 {
			time.Sleep(20 * time.Millisecond)
		}
		close(stop)
	}()
	b := &neverReportBackend{submitDelay: map[string]time.Duration{
		"b.bin": 200 * time.Millisecond, "c.bin": 200 * time.Millisecond,
		"d.bin": 200 * time.Millisecond}}
	start := time.Now()
	runPipeline(t, ctx, db, b, makeItems(t, "a.bin", "b.bin", "c.bin",
		"d.bin"), 1)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("pipeline took %s to stop", el)
	}
	for k, v := range statusOf(t, db) {
		if v == "failed" || v == "timeout" {
			t.Fatalf("%s marked %s on interrupt", k, v)
		}
	}
}

// waitPipeline: stop → bounded wait for in-flight work, then report.
func TestWaitPipelineInterruptBounded(t *testing.T) {
	log := newLogger(false, "", 0, 0)
	done, stop := make(chan struct{}), make(chan struct{})
	close(stop)
	start := time.Now()
	if !waitPipeline(done, stop, 100*time.Millisecond, log) {
		t.Fatal("want interrupted=true")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("grace not bounded: %s", el)
	}
	done2 := make(chan struct{})
	close(done2)
	if waitPipeline(done2, make(chan struct{}), time.Hour, log) {
		t.Fatal("normal completion reported as interrupted")
	}
}

func newTestInterrupt() (*interruptCtl, chan os.Signal, chan int) {
	ic := newInterruptCtl()
	codes := make(chan int, 2)
	ic.exit = func(c int) { codes <- c }
	ic.forceWait = 200 * time.Millisecond
	return ic, make(chan os.Signal, 2), codes
}

// Ctrl-C before the pipeline starts (readiness wait, prompts): Python's
// KeyboardInterrupt is uncaught there → 130, no reports.
func TestInterruptBeforePipelineExits130(t *testing.T) {
	ic, sig, codes := newTestInterrupt()
	go ic.watch(sig, newLogger(false, "", 0, 0))
	sig <- os.Interrupt
	select {
	case c := <-codes:
		if c != 130 {
			t.Fatalf("exit %d, want 130", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no exit on pre-pipeline Ctrl-C")
	}
	select {
	case <-ic.stop:
		t.Fatal("stop must not be closed when exiting outright")
	default:
	}
}

// First Ctrl-C while the pipeline runs: Stop closes, no exit (main writes
// reports and exits with the normal summary-based code). Second Ctrl-C:
// exit 130, but only after reports finish or the bound elapses.
func TestInterruptFirstStopsSecondForcesAfterReports(t *testing.T) {
	ic, sig, codes := newTestInterrupt()
	ic.live.Store(true)
	go ic.watch(sig, newLogger(false, "", 0, 0))
	sig <- os.Interrupt
	select {
	case <-ic.stop:
	case <-time.After(2 * time.Second):
		t.Fatal("first Ctrl-C did not stop the pipeline")
	}
	select {
	case c := <-codes:
		t.Fatalf("first Ctrl-C exited (%d)", c)
	case <-time.After(100 * time.Millisecond):
	}
	sig <- os.Interrupt
	select {
	case c := <-codes:
		t.Fatalf("second Ctrl-C exited (%d) before reports/bound", c)
	case <-time.After(50 * time.Millisecond):
	}
	ic.markReportsDone()
	select {
	case c := <-codes:
		if c != 130 {
			t.Fatalf("exit %d, want 130", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Ctrl-C never exited")
	}
}

// Second Ctrl-C with reports stuck: exit 130 after the bound.
func TestInterruptSecondBoundedWhenReportsHang(t *testing.T) {
	ic, sig, codes := newTestInterrupt()
	ic.live.Store(true)
	go ic.watch(sig, newLogger(false, "", 0, 0))
	sig <- os.Interrupt
	<-ic.stop
	sig <- os.Interrupt
	select {
	case c := <-codes:
		if c != 130 {
			t.Fatalf("exit %d, want 130", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("force quit not bounded")
	}
}

// syncNeverBackend is a synchronous backend (IsSync → zero result pollers)
// that never gets far enough to submit in these tests.
type syncNeverBackend struct{ neverReportBackend }

func (b *syncNeverBackend) IsSync() bool { return true }

// runScanArgs: everything runScan needs to run without prompts or exits.
func runScanArgs(t *testing.T, names ...string) (*Args, string, string) {
	t.Helper()
	drive := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(drive, n),
			[]byte("content-"+n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a := integrationArgs()
	a.Drive = drive
	a.DBPath = "scan_state.db"
	a.ReadSpeedTest = "off"
	a.CleanupOldRecords = "never"
	a.RetentionDays = 30
	a.ReportWaitHours = 12
	return a, t.TempDir(), t.TempDir()
}

// runScanBounded drives the real runScan with a fake backend and fails
// (instead of freezing the suite) if it does not return within limit.
func runScanBounded(t *testing.T, a *Args, outDir, runDir string,
	be ScanBackend, ic *interruptCtl, limit time.Duration) map[string]any {
	t.Helper()
	old := newScanBackend
	newScanBackend = func(*Args) (ScanBackend, error) { return be, nil }
	defer func() { newScanBackend = old }()
	res := make(chan map[string]any, 1)
	go func() {
		res <- runScan(a, nil, outDir, runDir, newLogger(false, "", 0, 0), ic)
	}()
	select {
	case out := <-res:
		return out
	case <-time.After(limit):
		t.Fatalf("runScan did not return within %s", limit)
		return nil
	}
}

// M9 (C1 via the real runScan): zero pollers (sync backend) + a leftover
// in-flight row + max_in_flight=1 — only runScan's close(pollersGone)
// releases the throttle; without it the upload worker spins forever.
func TestRunScanThrottleReleasedWhenPollersGone(t *testing.T) {
	a, outDir, runDir := runScanArgs(t, "a.bin")
	a.MaxInFlight = 1
	a.UploadWorkers = 1
	seed, err := NewScanDB(filepath.Join(outDir, a.DBPath))
	if err != nil {
		t.Fatal(err)
	}
	seed.UpsertPending("leftover", "/x", "x", 1)
	seed.MarkSubmitted("leftover", "task/x", "detect")
	seed.Close()
	runScanBounded(t, a, outDir, runDir, &syncNeverBackend{},
		newInterruptCtl(), 20*time.Second)
	db, err := NewScanDB(filepath.Join(outDir, a.DBPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, v := range db.Verdicts("") {
		if v.RelPath == "a.bin" {
			if v.Status != "failed" ||
				!strings.Contains(v.Error, "max_in_flight") {
				t.Fatalf("status=%s error=%q", v.Status, v.Error)
			}
			return
		}
	}
	t.Fatal("a.bin row missing")
}

// M9 (E2 via the real runScan): first Ctrl-C while an upload is stuck —
// runScan's waitPipeline bounds the wait (interruptGrace) and still builds
// the output from DB state; nothing is marked failed.
func TestRunScanStopBoundedByGrace(t *testing.T) {
	a, outDir, runDir := runScanArgs(t, "slow.bin")
	a.UploadWorkers = 1
	be := &neverReportBackend{submitDelay: map[string]time.Duration{
		"slow.bin": 15 * time.Second}}
	ic := newInterruptCtl()
	time.AfterFunc(500*time.Millisecond, ic.Stop)
	start := time.Now()
	out := runScanBounded(t, a, outDir, runDir, be, ic, 10*time.Second)
	if el := time.Since(start); el > 8*time.Second {
		t.Fatalf("stop took %s (grace not applied)", el)
	}
	if out == nil || out["summary"] == nil {
		t.Fatalf("no output built after stop: %v", out)
	}
	db, err := NewScanDB(filepath.Join(outDir, a.DBPath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, v := range db.Verdicts("") {
		if v.Status == "failed" || v.Status == "timeout" {
			t.Fatalf("%s marked %s on interrupt", v.RelPath, v.Status)
		}
	}
}
