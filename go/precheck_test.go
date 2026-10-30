// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// precheck_test.go — mirror of tests/test_precheck.py: batching at
// ReputationBatchSize, classified -> done rows with backend='ticloud',
// UNKNOWN -> prehashed re-enqueue, skip_classified=false re-enqueues all,
// invalid_hashes logged, partial flush on timer and on channel close,
// fail-open on bulk errors, no file ever lost.
package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	pcSHA256a = strings.Repeat("a", 64)
	pcSHA256b = strings.Repeat("b", 64)
	pcSHA256c = strings.Repeat("c", 64)
)

func precheckTestArgs() *Args {
	a := testArgs()
	a.ReputationBatchSize = 100
	a.ReputationSkipClassified = true
	return a
}

func precheckTestCtx(a *Args, log *Logger) *ScanContext {
	return &ScanContext{Args: a, Counters: NewCounters(),
		Locks: NewKeyedLocks(), Log: log}
}

func precheckTestItem(sha, rel string) precheckItem {
	return precheckItem{Sha256: sha, AbsPath: "/abs/" + rel, RelPath: rel,
		Size: 3, Head: []byte("MZ"), Prehashed: true}
}

// precheckEntry renders one TCA-0101 extended entry echoing its sha256.
func precheckEntry(sha, status, extra string) string {
	return fmt.Sprintf(`{"sha256":%q,"status":%q%s}`, sha, status, extra)
}

func newPrecheckDB(t *testing.T, items []precheckItem) *ScanDB {
	t.Helper()
	db, err := NewScanDB(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		db.UpsertPending(it.Sha256, it.AbsPath, it.RelPath, it.Size)
	}
	return db
}

// runPrecheck feeds items, closes precheckQ, waits for the worker to drain
// and exit, then returns (re-enqueued items, ndjson path).
func runPrecheck(t *testing.T, ctx *ScanContext, db *ScanDB,
	c *TicloudClient, items []precheckItem) ([]precheckItem, string) {
	t.Helper()
	pq := make(chan precheckItem, len(items)+1)
	wq := make(chan precheckItem, len(items)+8)
	ndjson := filepath.Join(t.TempDir(), "r.ndjson")
	writer, err := NewResultsWriter(ndjson)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		precheckWorker(ctx, db, c, pq, wq, writer)
		close(done)
	}()
	for _, it := range items {
		pq <- it
	}
	close(pq) // channel close = feeder sentinel
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("precheckWorker did not exit after channel close")
	}
	writer.Close()
	close(wq)
	var enq []precheckItem
	for it := range wq {
		enq = append(enq, it)
	}
	return enq, ndjson
}

// rowState reads back the verdict-relevant columns of one uploads row.
func rowState(t *testing.T, db *ScanDB, sha string) (status, cls, backend string) {
	t.Helper()
	rows := db.qAll(`SELECT status,classification,backend FROM uploads
	                 WHERE sha256=?`, sha)
	if rows == nil {
		t.Fatal("select failed")
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("row %s missing", sha)
	}
	var clsN, beN sql.NullString
	if err := rows.Scan(&status, &clsN, &beN); err != nil {
		t.Fatal(err)
	}
	return status, clsN.String, beN.String
}

func ndjsonRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func TestPrecheckBatchesRespectBatchSize(t *testing.T) {
	s, c := newTicloudTestServer(t)
	a := precheckTestArgs()
	a.ReputationBatchSize = 2
	ctx := precheckTestCtx(a, newLogger(false, "", 0, 0))
	var items []precheckItem
	for i := 0; i < 5; i++ {
		items = append(items, precheckTestItem(
			fmt.Sprintf("%064x", i), fmt.Sprintf("f%d.bin", i)))
	}
	db := newPrecheckDB(t, items)
	defer db.Close()
	enq, _ := runPrecheck(t, ctx, db, c, items)
	if got := fmt.Sprint(*s.bulkSizes); got != "[2 2 1]" {
		t.Fatalf("bulk batch sizes=%s, want [2 2 1]", got)
	}
	if (*s.bulkQuery)["hash_type"] != "sha256" {
		t.Fatalf("bulk hash_type=%v, want sha256", (*s.bulkQuery)["hash_type"])
	}
	if len(enq) != 5 {
		t.Fatalf("enqueued=%d, want 5 (all UNKNOWN -> upload)", len(enq))
	}
	for _, it := range enq {
		if !it.Prehashed {
			t.Fatal("re-enqueued item lost prehashed flag")
		}
	}
}

func TestPrecheckClassifiedMarksDoneTicloud(t *testing.T) {
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS",
			`,"threat_name":"Win32.Backdoor.Poison","threat_level":9,`+
				`"trust_factor":0`) + `],"invalid_hashes":[]}}`
	}
	items := []precheckItem{precheckTestItem(pcSHA256a, "evil.exe")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, ndjson := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 0 {
		t.Fatalf("classified item re-enqueued: %v", enq)
	}
	st, cls, be := rowState(t, db, pcSHA256a)
	if st != "done" || cls != "malicious" || be != "ticloud" {
		t.Fatalf("row=%s %s %s, want done/malicious/ticloud", st, cls, be)
	}
	rows := db.qAll(`SELECT threat_name,threat_factor,report_json
	                 FROM uploads WHERE sha256=?`, pcSHA256a)
	if rows == nil || !rows.Next() {
		t.Fatal("verdict row missing")
	}
	var tn string
	var tf int64
	var rj string
	rows.Scan(&tn, &tf, &rj)
	rows.Close()
	if tn != "Win32.Backdoor.Poison" || tf != 9 {
		t.Fatalf("threat=%q factor=%d", tn, tf)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(rj), &rep); err != nil ||
		rep["status"] != "MALICIOUS" {
		t.Fatalf("report_json should hold the raw entry: %s", rj)
	}
	recs := ndjsonRecords(t, ndjson)
	if len(recs) != 1 {
		t.Fatalf("ndjson lines=%d, want 1", len(recs))
	}
	rec := recs[0]
	if rec["classification"] != "malicious" || rec["backend"] != "ticloud" ||
		rec["sha256"] != pcSHA256a || rec["file_path"] != "evil.exe" {
		t.Fatalf("bad record: %v", rec)
	}
	if rec["threat_factor"].(float64) != 9 {
		t.Fatalf("threat_factor=%v", rec["threat_factor"])
	}
	if api, _ := rec["api"].(map[string]any); api == nil ||
		api["status"] != "completed" {
		t.Fatalf("bad api block: %v", rec["api"])
	}
	if ctx.Counters.Snapshot()["malicious"] != 1 {
		t.Fatal("malicious counter not incremented")
	}
}

func TestPrecheckKnownMapsToGoodwareTrustFactor(t *testing.T) {
	// KNOWN -> goodware with trust_factor — the normalized verdict, not the
	// raw fields, reaches MarkDoneDirect.
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "KNOWN",
			`,"threat_level":9,"trust_factor":2`) + `],"invalid_hashes":[]}}`
	}
	items := []precheckItem{precheckTestItem(pcSHA256a, "clean.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	runPrecheck(t, ctx, db, c, items)
	st, cls, _ := rowState(t, db, pcSHA256a)
	if st != "done" || cls != "goodware" {
		t.Fatalf("row=%s %s, want done/goodware", st, cls)
	}
	rows := db.qAll(`SELECT threat_factor FROM uploads WHERE sha256=?`,
		pcSHA256a)
	if rows == nil || !rows.Next() {
		t.Fatal("row missing")
	}
	var tf int64
	rows.Scan(&tf)
	rows.Close()
	if tf != 2 {
		t.Fatalf("threat_factor=%d, want 2 (trust_factor)", tf)
	}
}

func TestPrecheckUnknownReenqueuesPrehashed(t *testing.T) {
	// UNKNOWN -> item flows to workQ verbatim (prehashed) and the row stays
	// pending — the upload path owns it now.
	_, c := newTicloudTestServer(t) // default bulkFn answers UNKNOWN
	items := []precheckItem{precheckTestItem(pcSHA256a, "mystery.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, ndjson := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 1 || enq[0].Sha256 != pcSHA256a || !enq[0].Prehashed {
		t.Fatalf("enq=%v, want the same prehashed item", enq)
	}
	st, _, _ := rowState(t, db, pcSHA256a)
	if st != "pending" {
		t.Fatalf("status=%s, want pending", st)
	}
	if recs := ndjsonRecords(t, ndjson); len(recs) != 0 {
		t.Fatalf("ndjson lines=%d, want 0", len(recs))
	}
}

func TestPrecheckMissingEntryRoutesToUpload(t *testing.T) {
	// A hash absent from the response is treated like UNKNOWN.
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS",
			"") + `],"invalid_hashes":[]}}`
	}
	items := []precheckItem{precheckTestItem(pcSHA256a, "a.bin"),
		precheckTestItem(pcSHA256b, "b.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, _ := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 1 || enq[0].Sha256 != pcSHA256b {
		t.Fatalf("enq=%v, want [b]", enq)
	}
	if got := db.Counts(); got["done"] != 1 || got["pending"] != 1 {
		t.Fatalf("counts=%v", got)
	}
}

func TestPrecheckSkipClassifiedFalseReenqueuesAll(t *testing.T) {
	// skip_classified=false = enrichment-only: the reputation verdict lands
	// in NDJSON but the row stays pending — a 'done' row would let the
	// upload path's resume dedup short-circuit and the file never uploads.
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS", "") +
			`,` + precheckEntry(pcSHA256b, "UNKNOWN", "") +
			`],"invalid_hashes":[]}}`
	}
	a := precheckTestArgs()
	a.ReputationSkipClassified = false
	items := []precheckItem{precheckTestItem(pcSHA256a, "a.bin"),
		precheckTestItem(pcSHA256b, "b.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(a, newLogger(false, "", 0, 0))
	enq, ndjson := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 2 {
		t.Fatalf("enq=%d, want 2 (all re-enqueued)", len(enq))
	}
	if got := db.Counts(); got["pending"] != 2 || len(got) != 1 {
		t.Fatalf("counts=%v, want pending:2 only", got)
	}
	found := false
	for _, r := range ndjsonRecords(t, ndjson) {
		if r["sha256"] == pcSHA256a && r["backend"] == "ticloud" &&
			r["classification"] == "malicious" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing ticloud enrichment record for classified item")
	}
}

func TestPrecheckInvalidHashesLoggedNotLost(t *testing.T) {
	// invalid_hashes entries are logged; the affected items get no entry and
	// flow to the upload path.
	s, c := newTicloudTestServer(t)
	bad := "zz"
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS", "") +
			`],"invalid_hashes":[{"hash_value":"` + bad + bad + `"}]}}`
	}
	var buf bytes.Buffer
	log := &Logger{out: &buf}
	ctx := precheckTestCtx(precheckTestArgs(), log)
	items := []precheckItem{precheckTestItem(pcSHA256a, "a.bin"),
		precheckTestItem(pcSHA256b, "b.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	enq, _ := runPrecheck(t, ctx, db, c, items)
	if !strings.Contains(buf.String(), "invalid hash") {
		t.Fatalf("invalid_hashes not logged: %q", buf.String())
	}
	if len(enq) != 1 || enq[0].Sha256 != pcSHA256b {
		t.Fatalf("enq=%v, want [b]", enq)
	}
}

func TestPrecheckPartialBatchFlushesOnTimer(t *testing.T) {
	// Fewer than batch_size items must flush after the drain timer — the
	// tail can't wait for a full batch forever.
	s, c := newTicloudTestServer(t)
	a := precheckTestArgs()
	ctx := precheckTestCtx(a, newLogger(false, "", 0, 0))
	var items []precheckItem
	for i := 0; i < 3; i++ {
		items = append(items, precheckTestItem(
			fmt.Sprintf("%064x", i), fmt.Sprintf("f%d.bin", i)))
	}
	db := newPrecheckDB(t, items)
	defer db.Close()
	pq := make(chan precheckItem, 16)
	wq := make(chan precheckItem, 16)
	writer, err := NewResultsWriter(filepath.Join(t.TempDir(), "r.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		precheckWorker(ctx, db, c, pq, wq, writer)
		close(done)
	}()
	for _, it := range items {
		pq <- it // no close yet — the timer must flush the partial batch
	}
	deadline := time.Now().Add(15 * time.Second)
	for atomic.LoadInt32(s.bulkCalls) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if atomic.LoadInt32(s.bulkCalls) != 1 {
		t.Fatalf("bulkCalls=%d, want 1 (partial flush on timer)",
			atomic.LoadInt32(s.bulkCalls))
	}
	if got := fmt.Sprint(*s.bulkSizes); got != "[3]" {
		t.Fatalf("bulk sizes=%s, want [3]", got)
	}
	close(pq)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not exit after channel close")
	}
	writer.Close()
}

func TestPrecheckBulkFailureFailsOpen(t *testing.T) {
	// A persistently failing bulk call re-enqueues every item — files are
	// never lost, and the failure is counted separately.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		w.WriteHeader(503) // probe AND bulk both down
	}))
	t.Cleanup(srv.Close)
	c := NewTicloudClient(srv.URL, ticloudUser, ticloudPass, true, "",
		300*time.Second, 0, true)
	a := precheckTestArgs()
	a.MaxUploadAttempts = 2
	a.UploadRetryWindow = 1 // keeps the backoff sleeps sub-second
	items := []precheckItem{precheckTestItem(pcSHA256a, "a.bin"),
		precheckTestItem(pcSHA256b, "b.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(a, newLogger(false, "", 0, 0))
	enq, _ := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 2 {
		t.Fatalf("enq=%d, want 2 (nothing lost)", len(enq))
	}
	if got := db.Counts(); got["pending"] != 2 || len(got) != 1 {
		t.Fatalf("counts=%v, want {pending:2}", got)
	}
	if ctx.Counters.Snapshot()["precheck_errors"] != 1 {
		t.Fatal("precheck_errors not counted")
	}
}

func TestPrecheckRetriableRetriesThenSucceeds(t *testing.T) {
	// 429/5xx retry the whole batch with backoff; a later success lands the
	// verdicts normally.
	var bulkCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/" {
			w.WriteHeader(200)
			return
		}
		if atomic.AddInt32(&bulkCalls, 1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, `{"rl":{"entries":[`+
			precheckEntry(pcSHA256a, "SUSPICIOUS",
				`,"threat_level":5`)+`],"invalid_hashes":[]}}`)
	}))
	t.Cleanup(srv.Close)
	c := NewTicloudClient(srv.URL, ticloudUser, ticloudPass, true, "",
		300*time.Second, 0, true)
	a := precheckTestArgs()
	a.MaxUploadAttempts = 3
	a.UploadRetryWindow = 30
	items := []precheckItem{precheckTestItem(pcSHA256a, "a.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(a, newLogger(false, "", 0, 0))
	enq, _ := runPrecheck(t, ctx, db, c, items)
	if atomic.LoadInt32(&bulkCalls) != 2 {
		t.Fatalf("bulkCalls=%d, want 2 (retry)", atomic.LoadInt32(&bulkCalls))
	}
	if len(enq) != 0 {
		t.Fatalf("enq=%v, want []", enq)
	}
	st, cls, be := rowState(t, db, pcSHA256a)
	if st != "done" || cls != "suspicious" || be != "ticloud" {
		t.Fatalf("row=%s %s %s", st, cls, be)
	}
}

func TestPrecheckAuthErrorNotRetried(t *testing.T) {
	// 401/403 can never succeed on retry — fail open immediately.
	var bulkCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/" {
			w.WriteHeader(200)
			return
		}
		atomic.AddInt32(&bulkCalls, 1)
		w.WriteHeader(401)
	}))
	t.Cleanup(srv.Close)
	c := NewTicloudClient(srv.URL, ticloudUser, ticloudPass, true, "",
		300*time.Second, 0, true)
	a := precheckTestArgs()
	a.MaxUploadAttempts = 5
	items := []precheckItem{precheckTestItem(pcSHA256a, "a.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(a, newLogger(false, "", 0, 0))
	enq, _ := runPrecheck(t, ctx, db, c, items)
	if atomic.LoadInt32(&bulkCalls) != 1 {
		t.Fatalf("bulkCalls=%d, want 1 (no retry on auth)",
			atomic.LoadInt32(&bulkCalls))
	}
	if len(enq) != 1 {
		t.Fatalf("enq=%d, want 1", len(enq))
	}
}

func TestPrecheckDuplicateShaEachPathGetsRecord(t *testing.T) {
	// Two files with identical content share one sha256 row and one bulk
	// lookup, but every physical path gets its own verdict record (the dup
	// is flagged duplicate and does not alert again).
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS", "") +
			`],"invalid_hashes":[]}}`
	}
	items := []precheckItem{precheckTestItem(pcSHA256a, "a.exe"),
		precheckTestItem(pcSHA256a, "b.exe")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, ndjson := runPrecheck(t, ctx, db, c, items)
	if got := fmt.Sprint(*s.bulkSizes); got != "[1]" {
		t.Fatalf("bulk sizes=%s, want [1] (dedup)", got)
	}
	if got := db.Counts(); got["done"] != 1 || len(got) != 1 {
		t.Fatalf("counts=%v, want {done:1}", got)
	}
	recs := ndjsonRecords(t, ndjson)
	if len(recs) != 2 {
		t.Fatalf("ndjson lines=%d, want 2 (one per path)", len(recs))
	}
	paths := map[string]bool{}
	dups := 0
	for _, r := range recs {
		paths[r["file_path"].(string)] = true
		if r["duplicate"] == true {
			dups++
		}
	}
	if !paths["a.exe"] || !paths["b.exe"] || dups != 1 {
		t.Fatalf("records=%+v, want both paths + 1 dup flag", recs)
	}
	if ctx.Counters.Snapshot()["malicious"] != 2 {
		t.Fatal("malicious counter must be 2 (one per physical file)")
	}
	if len(enq) != 0 {
		t.Fatalf("enq=%v, want []", enq)
	}
}

func TestPrecheckFailedRowRequeuedAndVerdictPersisted(t *testing.T) {
	// A 'failed' row from a prior run is reset to pending by the re-upsert,
	// so the fresh synchronous verdict lands (counted fresh, not lost) and
	// the item is not re-enqueued for upload.
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS", "") +
			`],"invalid_hashes":[]}}`
	}
	items := []precheckItem{precheckTestItem(pcSHA256a, "prev-failed.exe")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	st500 := 500
	db.MarkFailed(pcSHA256a, &st500, "old failure")
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, ndjson := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 0 {
		t.Fatalf("enq=%v, want [] (verdict recorded)", enq)
	}
	st, _, _ := rowState(t, db, pcSHA256a)
	if st != "done" {
		t.Fatalf("status=%s, want done (fresh verdict persisted)", st)
	}
	if recs := ndjsonRecords(t, ndjson); len(recs) != 1 {
		t.Fatalf("ndjson lines=%d, want 1", len(recs))
	}
	if ctx.Counters.Snapshot()["malicious"] != 1 {
		t.Fatal("malicious counter must be 1 (fresh, not cached)")
	}
}

// M9: a verdict that can't stick (MarkDoneDirect flips 0 rows and the row
// is neither in-flight nor done) fails open: the item is re-enqueued for the
// upload path, no NDJSON record, no verdict counters.
func TestPrecheckVerdictCantStickFailsOpen(t *testing.T) {
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS", "") +
			`],"invalid_hashes":[]}}`
	}
	items := []precheckItem{precheckTestItem(pcSHA256a, "stuck.exe")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	// Make the pending->done UPDATE a silent no-op (0 rows affected).
	db.q(`CREATE TRIGGER no_done BEFORE UPDATE ON uploads
	      WHEN NEW.status='done' BEGIN SELECT RAISE(IGNORE); END`)
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, ndjson := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 1 || enq[0].Sha256 != pcSHA256a {
		t.Fatalf("enq=%v, want the item re-enqueued (fail open)", enq)
	}
	if st, _, _ := rowState(t, db, pcSHA256a); st != "pending" {
		t.Fatalf("status=%s, want pending", st)
	}
	if recs := ndjsonRecords(t, ndjson); len(recs) != 0 {
		t.Fatalf("ndjson lines=%d, want 0", len(recs))
	}
	if ctx.Counters.Snapshot()["malicious"] != 0 {
		t.Fatal("verdict counted although it never landed")
	}
}

func TestPrecheckRespectsSubmittedRow(t *testing.T) {
	// A row already 'submitted' is a live task — the verdict can't stick and
	// the item must NOT be re-enqueued (that would double-submit).
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS", "") +
			`],"invalid_hashes":[]}}`
	}
	items := []precheckItem{precheckTestItem(pcSHA256a, "live.exe")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	db.MarkSubmitted(pcSHA256a, "https://h/t/live")
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, _ := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 0 {
		t.Fatalf("enq=%v, want [] (dropped, not re-enqueued)", enq)
	}
	st, _, _ := rowState(t, db, pcSHA256a)
	if st != "submitted" {
		t.Fatalf("status=%s, want submitted", st)
	}
}

func TestPrecheckMalformedItemRoutedToUpload(t *testing.T) {
	// An item without a sha256 can't be queried — fail open with Prehashed
	// cleared so the upload path hashes it itself.
	s, c := newTicloudTestServer(t)
	items := []precheckItem{{AbsPath: "/abs/x.bin", RelPath: "x.bin",
		Prehashed: true}}
	db := newPrecheckDB(t, nil)
	defer db.Close()
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, _ := runPrecheck(t, ctx, db, c, items)
	if len(enq) != 1 || enq[0].Prehashed {
		t.Fatalf("enq=%v, want item with prehashed cleared", enq)
	}
	if ctx.Counters.Snapshot()["errors"] != 1 {
		t.Fatal("errors counter not incremented")
	}
	if atomic.LoadInt32(s.bulkCalls) != 0 {
		t.Fatal("malformed item must never reach the wire")
	}
}

func TestPrecheckSentinelExitsCleanlyWhenEmpty(t *testing.T) {
	// Worker must return on channel close even with nothing ever fed.
	s, c := newTicloudTestServer(t)
	db := newPrecheckDB(t, nil)
	defer db.Close()
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	enq, _ := runPrecheck(t, ctx, db, c, nil)
	if len(enq) != 0 {
		t.Fatalf("enq=%v, want []", enq)
	}
	if atomic.LoadInt32(s.bulkCalls) != 0 {
		t.Fatal("no bulk call expected for empty feed")
	}
}

func TestPrecheckBatchPanicNeverLosesItems(t *testing.T) {
	// A mid-batch blow-up is contained: every item re-enqueues to workQ
	// rather than vanishing. A nil *ResultsWriter makes writer.Write panic
	// after the first verdict lands — the flush recover must still route
	// BOTH items to the upload path.
	s, c := newTicloudTestServer(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` + precheckEntry(pcSHA256a, "MALICIOUS", "") +
			`,` + precheckEntry(pcSHA256b, "KNOWN", "") +
			`],"invalid_hashes":[]}}`
	}
	items := []precheckItem{precheckTestItem(pcSHA256a, "a.bin"),
		precheckTestItem(pcSHA256b, "b.bin")}
	db := newPrecheckDB(t, items)
	defer db.Close()
	ctx := precheckTestCtx(precheckTestArgs(), newLogger(false, "", 0, 0))
	pq := make(chan precheckItem, 4)
	wq := make(chan precheckItem, 8)
	var writer *ResultsWriter // Write() on a nil receiver panics
	done := make(chan struct{})
	go func() {
		precheckWorker(ctx, db, c, pq, wq, writer)
		close(done)
	}()
	for _, it := range items {
		pq <- it
	}
	close(pq)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not survive the panic")
	}
	close(wq)
	var enq []precheckItem
	for it := range wq {
		enq = append(enq, it)
	}
	if len(enq) != 2 {
		t.Fatalf("enq=%d, want 2 (nothing lost)", len(enq))
	}
	if ctx.Counters.Snapshot()["precheck_errors"] != 1 {
		t.Fatal("precheck_errors not counted")
	}
}
