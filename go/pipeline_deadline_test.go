// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// neverReportBackend accepts every upload (optionally slowly) and never
// returns a report — PollBatch always answers "pending".
type neverReportBackend struct {
	mu          sync.Mutex
	submitDelay map[string]time.Duration // by rel_path
	polled      map[string]bool          // refs seen by PollBatch
}

func (b *neverReportBackend) Name() string                                 { return "detect" }
func (b *neverReportBackend) NeedsSHA1() bool                              { return false }
func (b *neverReportBackend) IsSync() bool                                 { return false }
func (b *neverReportBackend) Probe(time.Duration) bool                     { return true }
func (b *neverReportBackend) WaitReady(_, _ time.Duration, _ *Logger) bool { return true }
func (b *neverReportBackend) AvailableNow(time.Duration) bool              { return true }
func (b *neverReportBackend) MarkUnavailable()                             {}
func (b *neverReportBackend) SubmitOnce(fp, sha, s1 string,
	meta map[string]any) SubmitOutcome {
	if d := b.submitDelay[fmt.Sprint(meta["rel_path"])]; d > 0 {
		time.Sleep(d)
	}
	return SubmitOutcome{Kind: "receipt", Ref: "task/" + sha}
}
func (b *neverReportBackend) SubmitWithBackoff(fp, sha, s1 string,
	meta map[string]any, a *Args, log *Logger) SubmitOutcome {
	return b.SubmitOnce(fp, sha, s1, meta)
}
func (b *neverReportBackend) PollBatch(refs []PollRef) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]any{}
	for _, r := range refs {
		if b.polled == nil {
			b.polled = map[string]bool{}
		}
		b.polled[r.Ref] = true
		out[r.Ref] = "pending"
	}
	return out
}

// runPipeline mirrors runScan's pool/poller wiring (uploadsDone,
// PollersGone) with a hard deadline so a hang fails instead of freezing.
func runPipeline(t *testing.T, ctx *ScanContext, db *ScanDB,
	backend ScanBackend, items chan workItem, nPollers int) {
	t.Helper()
	writer, _ := newIntegrationWriter(t)
	uploadsDone := make(chan struct{})
	pollersGone := make(chan struct{})
	ctx.PollersGone = pollersGone
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		var pollWG sync.WaitGroup
		go func() {
			defer close(uploadsDone)
			runUploadPool(ctx, db, backend, items, writer, nil)
		}()
		for i := 0; i < nPollers; i++ {
			pollWG.Add(1)
			go func() {
				defer pollWG.Done()
				resultPoller(ctx, db, backend, uploadsDone, writer)
			}()
		}
		go func() { pollWG.Wait(); close(pollersGone) }()
		<-uploadsDone
		<-pollersGone
		writer.Close()
	}()
	select {
	case <-finished:
	case <-time.After(45 * time.Second):
		t.Fatal("pipeline hung (no termination within 45s)")
	}
}

func statusOf(t *testing.T, db *ScanDB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, v := range db.Verdicts("") {
		out[v.RelPath] = v.Status
	}
	return out
}

func makeItems(t *testing.T, names ...string) chan workItem {
	t.Helper()
	dir := t.TempDir()
	var its []workItem
	for _, n := range names {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte("content-"+n), 0o644); err != nil {
			t.Fatal(err)
		}
		its = append(its, workItem{AbsPath: p, RelPath: n})
	}
	return feedItems(its...)
}

// C1: tiny report wait, max_in_flight=2, reports never arrive -> the run
// terminates, every row ends 'timeout' (none left submitted), exit non-zero.
func TestPerRowDeadlineThrottledRunTerminates(t *testing.T) {
	a := integrationArgs()
	a.MaxInFlight = 2
	ctx := integrationCtx(t, a)
	ctx.reportWait = time.Second
	db := newIntegrationDB(t)
	defer db.Close()
	runPipeline(t, ctx, db, &neverReportBackend{},
		makeItems(t, "a.bin", "b.bin", "c.bin", "d.bin"), 1)
	st := statusOf(t, db)
	if len(st) != 4 {
		t.Fatalf("rows=%v", st)
	}
	for k, v := range st {
		if v != "timeout" {
			t.Fatalf("%s status=%s, want timeout (all=%v)", k, v, st)
		}
	}
	out := buildOutputFromDB(a, db, ctx.Counters, "/", 4, nil,
		"1970-01-01 00:00:00")
	n, isInt := out["summary"].(map[string]any)["files_with_errors"].(int)
	if !isInt || n != 4 {
		t.Fatalf("files_with_errors=%v (int=%v), want int 4", n, isInt)
	}
}

// C1: a row submitted after run-start + wait still gets its own full wait:
// it is polled and then timed out, never stranded 'submitted'.
func TestPerRowDeadlineLateSubmissionPolled(t *testing.T) {
	a := integrationArgs()
	a.UploadWorkers = 1
	ctx := integrationCtx(t, a)
	ctx.reportWait = time.Second
	db := newIntegrationDB(t)
	defer db.Close()
	be := &neverReportBackend{submitDelay: map[string]time.Duration{
		"late.bin": 3 * time.Second}}
	runPipeline(t, ctx, db, be, makeItems(t, "early.bin", "late.bin"), 1)
	st := statusOf(t, db)
	if st["early.bin"] != "timeout" || st["late.bin"] != "timeout" {
		t.Fatalf("statuses=%v, want both timeout", st)
	}
	var lateSha string
	for _, v := range db.Verdicts("") {
		if v.RelPath == "late.bin" {
			lateSha = v.Sha256
		}
	}
	if !be.polled["task/"+lateSha] {
		t.Fatal("late submission was never polled")
	}
}

// C1: the throttle wait must not spin forever once pollers are gone (or the
// run is stopped) — pollers gone leaves the item failed with a clear error;
// a stop (Ctrl-C) leaves it pending for the next resume (R1).
func TestThrottleExitsWithoutPollers(t *testing.T) {
	for _, mode := range []string{"pollers_gone", "stop"} {
		t.Run(mode, func(t *testing.T) {
			a := integrationArgs()
			a.MaxInFlight = 1
			ctx := integrationCtx(t, a)
			gone := make(chan struct{})
			if mode == "stop" {
				// Stop fires while the item is already throttled (an item
				// dequeued after Stop is never started at all).
				ctx.Stop = gone
				time.AfterFunc(200*time.Millisecond, func() { close(gone) })
			} else {
				close(gone)
				ctx.PollersGone = gone
			}
			db := newIntegrationDB(t)
			defer db.Close()
			db.UpsertPending("inflight", "/x", "x", 1)
			db.MarkSubmitted("inflight", "task/x")
			f := writeFile(t, "t.bin", "throttled")
			sha := fileSHA256(t, f)
			wq := make(chan precheckItem, 1)
			wq <- precheckItem{AbsPath: f, RelPath: "t.bin", Raw: true}
			close(wq)
			var feedWG sync.WaitGroup
			feedWG.Add(1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				uploadWorker(ctx, db, &neverReportBackend{}, wq, nil,
					&feedWG, nil)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("throttle loop spun forever")
			}
			for _, v := range db.Verdicts("") {
				if v.Sha256 != sha {
					continue
				}
				if mode == "stop" {
					// R1: a Ctrl-C while throttled leaves the row
					// pending (resumable), never failed.
					if v.Status != "pending" || v.Error != "" {
						t.Fatalf("status=%s error=%q, want pending",
							v.Status, v.Error)
					}
					return
				}
				if v.Status != "failed" ||
					!strings.Contains(v.Error, "max_in_flight") {
					t.Fatalf("status=%s error=%q", v.Status, v.Error)
				}
				return
			}
			t.Fatal("row missing")
		})
	}
}

// R2: a row resumed from an earlier run (old uploaded_at) gets a fresh
// report window counted from this run's start — it is polled at least once
// and not expired before RunStartedAt + wait.
func TestResumedRowGetsFreshReportWindow(t *testing.T) {
	a := integrationArgs()
	ctx := integrationCtx(t, a)
	ctx.reportWait = 2 * time.Second
	db := newIntegrationDB(t)
	defer db.Close()
	db.UpsertPending("old", "/old", "old.bin", 1)
	db.MarkSubmitted("old", "task/old", "detect")
	db.q(`UPDATE uploads SET uploaded_at=datetime('now','-1 day'),
	      updated_at=datetime('now','-1 day') WHERE sha256='old'`)
	ctx.RunStartedAt = db.Now()
	be := &neverReportBackend{}
	start := time.Now()
	runPipeline(t, ctx, db, be, feedItems(), 1)
	if !be.polled["task/old"] {
		t.Fatal("resumed row expired before it was ever polled")
	}
	if st := statusOf(t, db)["old.bin"]; st != "timeout" {
		t.Fatalf("status=%s, want timeout", st)
	}
	if el := time.Since(start); el < time.Second {
		t.Fatalf("expired after %v, before run start + wait", el)
	}
}

func readLines(t *testing.T, p string) []string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sc.Text() != "" {
			out = append(out, sc.Text())
		}
	}
	return out
}

// C2: a resumed cached malicious hit runs alert + quarantine for a path that
// was not yet handled, emits a cached NDJSON record, persists the actions,
// and does not re-alert the same path on the next resumed pass.
func TestCachedHitRunsVerdictActionsOncePerPath(t *testing.T) {
	a := integrationArgs()
	a.Resume = true
	a.AlertOn = map[string]bool{"malicious": true}
	a.QuarantineOn = map[string]bool{"malicious": true}
	a.QuarantineAction = "copy"
	ctx := integrationCtx(t, a)
	alerts := filepath.Join(t.TempDir(), "alerts.jsonl")
	ctx.Alerter = NewAlerter(a.AlertOn, alerts, "", nil, false, ctx.Log)
	ctx.Quarantine = filepath.Join(t.TempDir(), "q")
	db := newIntegrationDB(t)
	defer db.Close()

	f := writeFile(t, "dup.bin", "evil")
	sha := fileSHA256(t, f)
	// Verdict recorded earlier for the same content at another path, with
	// actions handled there.
	db.UpsertPending(sha, "/elsewhere/orig.bin", "orig.bin", 4)
	db.MarkSubmitted(sha, "task/1")
	db.ClaimReport(sha)
	db.MarkDone(sha, "malicious", "Win.Evil", nil, nil)
	db.MarkActions(sha, "/q/old", true)

	run := func() string {
		w, p := newIntegrationWriter(t)
		wq := make(chan precheckItem, 1)
		wq <- precheckItem{AbsPath: f, RelPath: "dup.bin", Raw: true}
		close(wq)
		var feedWG sync.WaitGroup
		feedWG.Add(1)
		uploadWorker(ctx, db, &neverReportBackend{}, wq, nil, &feedWG, w)
		w.Close()
		return p
	}

	nd := run()
	if n := len(readLines(t, alerts)); n != 1 {
		t.Fatalf("alerts after first cached hit=%d, want 1", n)
	}
	lines := readLines(t, nd)
	if len(lines) != 1 {
		t.Fatalf("ndjson lines=%d, want 1", len(lines))
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["cached"] != true || rec["classification"] != "malicious" ||
		rec["alerted"] != true || rec["quarantined_to"] == nil ||
		rec["file_path"] != "dup.bin" {
		t.Fatalf("bad cached record: %v", rec)
	}
	api, _ := rec["api"].(map[string]any)
	if api["status"] != "cached" {
		t.Fatalf("api.status=%v, want cached", api["status"])
	}
	var v VerdictRow
	for _, r := range db.Verdicts("") {
		v = r
	}
	if v.Status != "cached" || v.Alerted == nil || *v.Alerted != 1 ||
		v.QuarantinedTo == "" || v.QuarantinedTo == "/q/old" {
		t.Fatalf("persisted actions: %+v", v)
	}
	if _, err := os.Stat(v.QuarantinedTo); err != nil {
		t.Fatalf("quarantine copy missing: %v", err)
	}

	// Same path again (resumed scan): already handled -> no alert spam, but
	// the cached hit is still recorded.
	nd2 := run()
	if n := len(readLines(t, alerts)); n != 1 {
		t.Fatalf("alerts after re-run on same path=%d, want 1", n)
	}
	if n := len(readLines(t, nd2)); n != 1 {
		t.Fatalf("ndjson lines on re-run=%d, want 1", n)
	}
}

// C3: summary cards come from the report rows, not per-run counters.
func TestSummaryCountsFromRows(t *testing.T) {
	a := integrationArgs()
	db := newIntegrationDB(t)
	defer db.Close()
	done := func(sha, cls string) {
		db.UpsertPending(sha, "/"+sha, sha, 1)
		db.MarkSubmitted(sha, "t/"+sha)
		db.ClaimReport(sha)
		db.MarkDone(sha, cls, "", nil, nil)
	}
	done("m1", "malicious")
	db.MarkActions("m1", "/q/m1", true)
	done("s1", "suspicious")
	db.MarkActions("s1", "", false)
	done("g1", "goodware")
	done("o1", "weird-label")
	done("c1", "malicious")
	db.MarkCached("c1")
	db.UpsertPending("f1", "/f1", "f1", 1)
	db.MarkFailed("f1", nil, "skipped_filetype:pe")
	db.UpsertPending("f2", "/f2", "f2", 1)
	db.MarkFailed("f2", nil, "boom")
	db.UpsertPending("t1", "/t1", "t1", 1)
	db.MarkSubmitted("t1", "t/t1")
	db.MarkReportTimeout("t1")
	db.UpsertPending("p1", "/p1", "p1", 1) // pending: no classification bucket

	c := NewCounters() // stale/garbage counters must not leak into cards
	c.Inc("malicious", 99)
	c.Inc("errors", 99)
	c.Inc("skipped_filetype", 1)
	out := buildOutputFromDB(a, db, c, "/", 9, nil, "1970-01-01 00:00:00")
	s := out["summary"].(map[string]any)
	want := map[string]int{"files_processed": 9, "malicious": 2,
		"suspicious": 1, "goodware": 1, "unknown": 0, "other": 1,
		"quarantined": 1, "alerts": 1, "files_with_errors": 2,
		"cached_hits": 1, "skipped_by_filetype": 1,
		"files_completed_successfully": 5}
	for k, w := range want {
		got, isInt := s[k].(int)
		if !isInt || got != w {
			t.Errorf("%s=%v (int=%v), want %d", k, s[k], isInt, w)
		}
	}
}

// instantVerdictBackend: receipt on submit, verdict on the first poll.
type instantVerdictBackend struct {
	neverReportBackend
}

func (b *instantVerdictBackend) PollBatch(refs []PollRef) map[string]any {
	f := int64(9)
	out := map[string]any{}
	for _, r := range refs {
		out[r.Ref] = map[string]any{
			"classification": "malicious",
			"threat_name":    "Trojan.X",
			"threat_factor":  &f,
			"report_json":    nil,
		}
	}
	return out
}

// C2b: two copies of the same content in one run — the hash's row tracks
// the submitter's path; the duplicate still gets quarantine + its own
// NDJSON row when the verdict drains.
func TestInflightDuplicatePathsAllGetActions(t *testing.T) {
	a := integrationArgs()
	a.QuarantineOn = map[string]bool{"malicious": true}
	a.QuarantineAction = "copy"
	ctx := integrationCtx(t, a)
	ctx.Quarantine = t.TempDir()
	db := newIntegrationDB(t)
	defer db.Close()
	writer, ndjson := newIntegrationWriter(t)
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.exe")
	if err := os.WriteFile(f1, []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f2 := filepath.Join(sub, "b.exe")
	if err := os.WriteFile(f2, []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	drivePoolPoll(t, ctx, db, &instantVerdictBackend{}, feedItems(
		workItem{AbsPath: f1, RelPath: "a.exe"},
		workItem{AbsPath: f2, RelPath: "sub/b.exe"}), writer, nil, true)
	writer.Close()

	recs := ndjsonRecords(t, ndjson)
	if len(recs) != 2 {
		t.Fatalf("ndjson records=%d, want 2 (one per path): %+v",
			len(recs), recs)
	}
	paths := map[string]bool{}
	dups := 0
	for _, r := range recs {
		abs, _ := r["absolute_path"].(string)
		paths[abs] = true
		if r["duplicate"] == true {
			dups++
		}
		qt, _ := r["quarantined_to"].(string)
		if qt == "" {
			t.Fatalf("no quarantine dest in %+v", r)
		}
		if _, err := os.Stat(qt); err != nil {
			t.Fatalf("quarantined copy missing: %v", err)
		}
	}
	if !paths[f1] || !paths[f2] {
		t.Fatalf("want records for both paths, got %v", paths)
	}
	if dups != 1 {
		t.Fatalf("duplicate-flagged records=%d, want 1", dups)
	}
	if n := ctx.Counters.Snapshot()["quarantined"]; n != 2 {
		t.Fatalf("quarantined=%d, want 2", n)
	}
}

// C2b: a cached malicious verdict re-encountered at two new paths in one
// run — each physical copy gets its own actions + NDJSON record; alerts
// fire per path (each location is a new detection event).
func TestCachedDuplicateAtSecondPathActsAgain(t *testing.T) {
	a := integrationArgs()
	a.Resume = true
	a.AlertOn = map[string]bool{"malicious": true}
	a.QuarantineOn = map[string]bool{"malicious": true}
	a.QuarantineAction = "copy"
	ctx := integrationCtx(t, a)
	alerts := filepath.Join(t.TempDir(), "alerts.jsonl")
	ctx.Alerter = NewAlerter(a.AlertOn, alerts, "", nil, false, ctx.Log)
	ctx.Quarantine = filepath.Join(t.TempDir(), "q")
	db := newIntegrationDB(t)
	defer db.Close()

	f1 := writeFile(t, "place.exe", "evil")
	sub := filepath.Join(filepath.Dir(f1), "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f2 := filepath.Join(sub, "copy.exe")
	if err := os.WriteFile(f2, []byte("evil"), 0o644); err != nil {
		t.Fatal(err)
	}
	sha := fileSHA256(t, f1)
	db.UpsertPending(sha, "/old/place.exe", "place.exe", 4)
	db.MarkSubmitted(sha, "task/1")
	db.ClaimReport(sha)
	db.MarkDone(sha, "malicious", "Trojan.X", nil, nil)

	w, ndjson := newIntegrationWriter(t)
	wq := make(chan precheckItem, 2)
	wq <- precheckItem{AbsPath: f1, RelPath: "place.exe", Raw: true}
	wq <- precheckItem{AbsPath: f2, RelPath: "sub/copy.exe", Raw: true}
	close(wq)
	var feedWG sync.WaitGroup
	feedWG.Add(2)
	uploadWorker(ctx, db, &neverReportBackend{}, wq, nil, &feedWG, w)
	w.Close()

	if n := len(readLines(t, alerts)); n != 2 {
		t.Fatalf("alerts=%d, want 2 (one per path)", n)
	}
	recs := ndjsonRecords(t, ndjson)
	if len(recs) != 2 {
		t.Fatalf("ndjson records=%d, want 2", len(recs))
	}
	paths := map[string]bool{}
	for _, r := range recs {
		paths[r["absolute_path"].(string)] = true
	}
	if !paths[f1] || !paths[f2] {
		t.Fatalf("want records for both paths, got %v", paths)
	}
}
