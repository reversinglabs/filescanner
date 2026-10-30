// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// integration_test.go — end-to-end pipeline coverage for the multi-backend
// dispatch (mirror of tests/test_pipeline_backends.py): runUploadPool +
// resultPoller driven against the real httptest backend servers — FIE sync
// verdicts with no poll phase, A1000 submit/status/classification, Cloud
// two-step sha1 upload + reputation poll, the reputation pre-check handoff
// (classified -> done, unknown -> upload), and Detect regression.
package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func integrationCtx(t *testing.T, a *Args) *ScanContext {
	t.Helper()
	return &ScanContext{Args: a, Counters: NewCounters(),
		Locks: NewKeyedLocks(), Log: newLogger(false, "", 0, 0),
		reportWait: 30 * time.Second}
}

func integrationArgs() *Args {
	a := testArgs()
	a.UploadWorkers = 2
	a.ResultPollInterval = 0 // pollIteration still sleeps max(1,0)=1s
	a.Resume = false
	a.ReputationBatchSize = 100
	a.ReputationSkipClassified = true
	return a
}

func feedItems(items ...workItem) chan workItem {
	ch := make(chan workItem, len(items)+1)
	for _, it := range items {
		ch <- it
	}
	close(ch)
	return ch
}

func newIntegrationDB(t *testing.T) *ScanDB {
	t.Helper()
	db, err := NewScanDB(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func newIntegrationWriter(t *testing.T) (*ResultsWriter, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.ndjson")
	w, err := NewResultsWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	return w, p
}

// drivePoolPoll mirrors runScan's core: the upload pool feeds workers; for
// async backends one resultPoller resolves receipts until uploads_done and
// the submitted set drains.
func drivePoolPoll(t *testing.T, ctx *ScanContext, db *ScanDB,
	backend ScanBackend, workIter chan workItem, writer *ResultsWriter,
	precheck *TicloudClient, poll bool) {
	t.Helper()
	uploadsDone := make(chan struct{})
	var pollDone chan struct{}
	if poll {
		pollDone = make(chan struct{})
		go func() {
			defer close(pollDone)
			resultPoller(ctx, db, backend, uploadsDone, writer)
		}()
	}
	runUploadPool(ctx, db, backend, workIter, writer, precheck)
	close(uploadsDone)
	if poll {
		select {
		case <-pollDone:
		case <-time.After(60 * time.Second):
			t.Fatal("resultPoller did not exit after uploads_done")
		}
	}
}

// -- FIE: synchronous verdict on submit, zero pollers ------------------------

func TestIntegrationFieSyncDoneNoPoller(t *testing.T) {
	s, b := newFieTestServer(t, 200,
		`{"classification":"malicious","threat_details":`+
			`{"threat_name":"Win32.Evil","scanner_match":37}}`, `{}`)
	f := writeFile(t, "a.exe", "MZ-a")
	sha256, sha1Want := fileSHA256(t, f), fileSHA1(t, f)

	db := newIntegrationDB(t)
	writer, ndjson := newIntegrationWriter(t)
	drivePoolPoll(t, integrationCtx(t, integrationArgs()), db, b,
		feedItems(workItem{AbsPath: f, RelPath: "a.exe"}), writer,
		nil, false) // is_sync -> no poller ever spawns
	writer.Close()

	if *s.checkCalls != 1 || *s.scanCalls != 0 {
		t.Fatalf("hash_then_scan verdict must stop at check_hash: "+
			"check=%d scan=%d", *s.checkCalls, *s.scanCalls)
	}
	st, cls, be := rowState(t, db, sha256)
	if st != "done" || cls != "malicious" || be != "fie" {
		t.Fatalf("bad row: %s %s %s", st, cls, be)
	}
	var dbSha1 string
	rows := db.qAll("SELECT sha1 FROM uploads WHERE sha256=?", sha256)
	defer rows.Close()
	if rows.Next() {
		rows.Scan(&dbSha1)
	}
	if dbSha1 != sha1Want {
		t.Fatalf("needs_sha1 backend must persist sha1: %q", dbSha1)
	}
	recs := ndjsonRecords(t, ndjson)
	if len(recs) != 1 || recs[0]["backend"] != "fie" ||
		recs[0]["classification"] != "malicious" {
		t.Fatalf("bad ndjson record: %+v", recs)
	}
}

func TestIntegrationFieRelPathExternalID(t *testing.T) {
	// meta['rel_path'] must reach the backend — external_id mode rel_path
	// resolves to the scan-root-relative path.
	s, b := newFieTestServer(t, 200, `{}`,
		`{"classification":"OK"}`)
	b.mode = "scan"
	f := writeFile(t, "b.exe", "MZ-b")

	db := newIntegrationDB(t)
	writer, _ := newIntegrationWriter(t)
	drivePoolPoll(t, integrationCtx(t, integrationArgs()), db, b,
		feedItems(workItem{AbsPath: f, RelPath: "sub/b.exe"}), writer,
		nil, false)
	writer.Close()

	if *s.externalID != "sub/b.exe" {
		t.Fatalf("external_id want sub/b.exe, got %q", *s.externalID)
	}
}

// -- A1000: submit -> sha1 receipt -> status_bulk -> classification ----------

func TestIntegrationA1000SubmitPollDone(t *testing.T) {
	s, b := newA1000TestServer(t)
	f := writeFile(t, "a.exe", "MZ-a")
	sha256 := fileSHA256(t, f)

	db := newIntegrationDB(t)
	writer, ndjson := newIntegrationWriter(t)
	drivePoolPoll(t, integrationCtx(t, integrationArgs()), db, b,
		feedItems(workItem{AbsPath: f, RelPath: "a.exe"}), writer,
		nil, true)
	writer.Close()

	if atomic.LoadInt32(s.uploadCalls) != 1 {
		t.Fatalf("upload calls: %d", *s.uploadCalls)
	}
	if atomic.LoadInt32(s.statusCalls) < 1 ||
		atomic.LoadInt32(s.clsCalls) < 1 {
		t.Fatalf("poll path must hit status+classification: %d %d",
			*s.statusCalls, *s.clsCalls)
	}
	st, cls, be := rowState(t, db, sha256)
	if st != "done" || cls != "malicious" || be != "a1000" {
		t.Fatalf("bad row: %s %s %s", st, cls, be)
	}
	var tu string
	rows := db.qAll("SELECT task_url FROM uploads WHERE sha256=?", sha256)
	defer rows.Close()
	if rows.Next() {
		rows.Scan(&tu)
	}
	if tu != a1000SHA1 {
		t.Fatalf("a1000 receipt ref is its sha1, got %q", tu)
	}
	recs := ndjsonRecords(t, ndjson)
	if len(recs) != 1 || recs[0]["backend"] != "a1000" {
		t.Fatalf("bad ndjson record: %+v", recs)
	}
}

// -- Cloud: spex two-step -> sha1 receipt -> TCA-0101 reputation poll --------

func TestIntegrationCloudTwoStepPollDone(t *testing.T) {
	s, b := newCloudBackend(t)
	s.bulkFn = func(hashes []string) string {
		var sb strings.Builder
		sb.WriteString(`{"rl":{"entries":[`)
		for i, h := range hashes {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"sha1":%q,"status":"MALICIOUS",`+
				`"threat_name":"Win32.Trojan","threat_level":9}`, h)
		}
		sb.WriteString(`],"invalid_hashes":[]}}`)
		return sb.String()
	}
	f := writeFile(t, "a.exe", "MZ-a")
	sha256, sha1Want := fileSHA256(t, f), fileSHA1(t, f)

	db := newIntegrationDB(t)
	writer, ndjson := newIntegrationWriter(t)
	drivePoolPoll(t, integrationCtx(t, integrationArgs()), db, b,
		feedItems(workItem{AbsPath: f, RelPath: "a.exe"}), writer,
		nil, true)
	writer.Close()

	if atomic.LoadInt32(s.uploadCalls) != 1 ||
		atomic.LoadInt32(s.metaCalls) != 1 {
		t.Fatalf("spex two-step wants upload+meta: %d %d",
			*s.uploadCalls, *s.metaCalls)
	}
	if (*s.bulkQuery)["hash_type"] != "sha1" {
		t.Fatalf("cloud must poll by sha1: %+v", *s.bulkQuery)
	}
	st, cls, be := rowState(t, db, sha256)
	if st != "done" || cls != "malicious" || be != "cloud" {
		t.Fatalf("bad row: %s %s %s", st, cls, be)
	}
	var tu, dbSha1 string
	rows := db.qAll("SELECT task_url,sha1 FROM uploads WHERE sha256=?",
		sha256)
	defer rows.Close()
	if rows.Next() {
		rows.Scan(&tu, &dbSha1)
	}
	if tu != sha1Want || dbSha1 != sha1Want {
		t.Fatalf("cloud ref==sha1 and sha1 persisted: %q %q", tu, dbSha1)
	}
	recs := ndjsonRecords(t, ndjson)
	if len(recs) != 1 || recs[0]["backend"] != "cloud" {
		t.Fatalf("bad ndjson record: %+v", recs)
	}
}

// -- Reputation pre-check: classified short-circuits, unknown goes to upload --

func TestIntegrationPrecheckClassifiedDoneUnknownUploads(t *testing.T) {
	report := `{"processed":1,"tc_report":[{"classification":` +
		`{"classification":1,"factor":0,"result":"clean"}}]}`
	_, det := detectTestServer(t, report, 200)
	tcSrv, tcClient := newTicloudTestServer(t)

	known := writeFile(t, "known.exe", "MZ-known")
	novo := writeFile(t, "new.exe", "MZ-new")
	shaKnown := fileSHA256(t, known)
	shaNew := fileSHA256(t, novo)

	tcSrv.bulkFn = func(hashes []string) string {
		var sb strings.Builder
		sb.WriteString(`{"rl":{"entries":[`)
		first := true
		for _, h := range hashes {
			if h != shaKnown {
				continue // no entry -> unknown -> upload path
			}
			if !first {
				sb.WriteString(",")
			}
			first = false
			fmt.Fprintf(&sb, `{"sha256":%q,"status":"MALICIOUS",`+
				`"threat_name":"Known.Bad","threat_level":7}`, h)
		}
		sb.WriteString(`],"invalid_hashes":[]}}`)
		return sb.String()
	}

	db := newIntegrationDB(t)
	writer, _ := newIntegrationWriter(t)
	drivePoolPoll(t, integrationCtx(t, integrationArgs()), db, det,
		feedItems(workItem{AbsPath: known, RelPath: "known.exe"},
			workItem{AbsPath: novo, RelPath: "new.exe"}),
		writer, tcClient, true)
	writer.Close()

	st, cls, be := rowState(t, db, shaKnown)
	if st != "done" || cls != "malicious" || be != "ticloud" {
		t.Fatalf("precheck verdict row: %s %s %s", st, cls, be)
	}
	st, cls, be = rowState(t, db, shaNew)
	if st != "done" || cls != "goodware" || (be != "detect" && be != "") {
		t.Fatalf("upload-path row: %s %s %q", st, cls, be)
	}
	// Exactly one Detect upload: the unknown file. The classified file
	// must never reach the submit path — precheck-done rows carry a NULL
	// task_url, so exactly one row must have a receipt.
	rows := db.qAll("SELECT COUNT(*) FROM uploads WHERE task_url IS NOT NULL")
	defer rows.Close()
	var n int
	if rows.Next() {
		rows.Scan(&n)
	}
	if n != 1 {
		t.Fatalf("want exactly 1 submitted receipt, got %d", n)
	}
}

// skip_classified=false + resume=true: the reputation-verdicted file must
// still reach the backend — before the fix the fresh 'done' row made the
// resume dedup mark it 'cached' and the backend never saw the upload.
func TestIntegrationPrecheckEnrichmentStillUploads(t *testing.T) {
	report := `{"processed":1,"tc_report":[{"classification":` +
		`{"classification":1,"factor":0,"result":"clean"}}]}`
	_, det := detectTestServer(t, report, 200)
	tcSrv, tcClient := newTicloudTestServer(t)

	known := writeFile(t, "known.exe", "MZ-known")
	shaKnown := fileSHA256(t, known)

	tcSrv.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[{"sha256":` + `"` + shaKnown + `",` +
			`"status":"MALICIOUS","threat_name":"Known.Bad",` +
			`"threat_level":7}],"invalid_hashes":[]}}`
	}

	a := integrationArgs()
	a.ReputationSkipClassified = false
	a.Resume = true
	db := newIntegrationDB(t)
	writer, ndjson := newIntegrationWriter(t)
	drivePoolPoll(t, integrationCtx(t, a), db, det,
		feedItems(workItem{AbsPath: known, RelPath: "known.exe"}),
		writer, tcClient, true)
	writer.Close()

	// The backend owns the final verdict — detect's goodware, not the
	// ticloud enrichment.
	st, cls, be := rowState(t, db, shaKnown)
	if st != "done" || cls != "goodware" || (be != "detect" && be != "") {
		t.Fatalf("backend verdict should own the row: %s %s %q", st, cls, be)
	}
	rows := db.qAll("SELECT task_url FROM uploads WHERE sha256=?", shaKnown)
	if rows == nil {
		t.Fatal("select failed")
	}
	defer rows.Close()
	var tu sql.NullString
	if !rows.Next() || rows.Scan(&tu) != nil || !tu.Valid {
		t.Fatal("file never uploaded — missing task_url receipt")
	}
	// The enrichment evidence still landed in NDJSON.
	found := false
	for _, r := range ndjsonRecords(t, ndjson) {
		if r["backend"] == "ticloud" && r["classification"] == "malicious" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing ticloud enrichment record in ndjson")
	}
}

// -- Detect regression --------------------------------------------------------

func TestIntegrationDetectRecordHasNoBackendKey(t *testing.T) {
	report := `{"processed":1,"tc_report":[{"classification":` +
		`{"classification":3,"factor":8,"result":"Trojan.X"}}]}`
	srv, det := detectTestServer(t, report, 200)
	f := writeFile(t, "a.exe", "MZ-a")
	sha256 := fileSHA256(t, f)

	db := newIntegrationDB(t)
	writer, ndjson := newIntegrationWriter(t)
	drivePoolPoll(t, integrationCtx(t, integrationArgs()), db, det,
		feedItems(workItem{AbsPath: f, RelPath: "a.exe"}), writer,
		nil, true)
	writer.Close()

	st, cls, be := rowState(t, db, sha256)
	if st != "done" || cls != "malicious" || (be != "detect" && be != "") {
		t.Fatalf("detect row: %s %s %q", st, cls, be)
	}
	recs := ndjsonRecords(t, ndjson)
	if len(recs) != 1 {
		t.Fatalf("records: %+v", recs)
	}
	if _, has := recs[0]["backend"]; has {
		t.Fatalf("detect record must carry no backend key: %+v", recs[0])
	}
	if recs[0]["task_url"] != srv.URL+"/task/1" {
		t.Fatalf("task_url: %v", recs[0]["task_url"])
	}
}

// -- helpers -----------------------------------------------------------------

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func fileSHA1(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha1.Sum(b))
}
