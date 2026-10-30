// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// db_test.go — mirror of tests/test_scandb.py for the multi-backend
// additions: old-schema migration, MarkDoneDirect, ResetSubmittedForBackend.
package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// uploads schema before the sha1/backend columns existed.
const oldUploadsSchema = `
CREATE TABLE uploads(
    sha256 TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    file_size INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    task_url TEXT,
    http_status INTEGER,
    error TEXT,
    attempts INTEGER DEFAULT 0,
    classification TEXT,
    threat_name TEXT,
    threat_factor INTEGER,
    report_json TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    uploaded_at TEXT,
    report_fetched_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_status ON uploads(status);
`

func TestScanDBMigratesOldSchema(t *testing.T) {
	// Pre-multi-backend state DBs must open cleanly, gain sha1+backend
	// columns, and keep every existing row — resume state is cross-run.
	path := filepath.Join(t.TempDir(), "s.db")
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(oldUploadsSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO uploads(sha256,file_path,rel_path,
		file_size,status,task_url) VALUES('aa','f','r',1,'submitted','u1')`); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	db, err := NewScanDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rows := db.qAll(`SELECT sha256,status,task_url,backend FROM uploads`)
	if rows == nil {
		t.Fatal("SELECT incl. new columns failed — migration did not run")
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var sha, st, tu string
		var be sql.NullString
		if err := rows.Scan(&sha, &st, &tu, &be); err != nil {
			t.Fatal(err)
		}
		if sha != "aa" || st != "submitted" || tu != "u1" || be.Valid {
			t.Fatalf("row mangled: %v %v %v %v", sha, st, tu, be)
		}
		n++
	}
	if n != 1 {
		t.Fatalf("expected 1 preserved row, got %d", n)
	}
}

func TestMarkDoneDirect(t *testing.T) {
	// FIE sync verdicts and reputation pre-check write 'done' straight from
	// 'pending' — there is no submit/claim round-trip to wait on.
	db, err := NewScanDB(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.UpsertPending("aa", "f", "a", 1)
	factor := int64(5)
	report := `{"r":1}`
	db.MarkDoneDirect("aa", "malicious", "Trojan.X", &factor, &report, "fie")

	rows := db.qAll(`SELECT status,classification,threat_name,threat_factor,
		report_json,backend FROM uploads WHERE sha256='aa'`)
	if rows == nil {
		t.Fatal("select failed")
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("row missing")
	}
	var st, cls, tn, rj, be string
	var tf sql.NullInt64
	var tnN, rjN sql.NullString
	if err := rows.Scan(&st, &cls, &tnN, &tf, &rjN, &be); err != nil {
		t.Fatal(err)
	}
	tn, rj = tnN.String, rjN.String
	if st != "done" || cls != "malicious" || tn != "Trojan.X" ||
		!tf.Valid || tf.Int64 != 5 || rj != `{"r":1}` || be != "fie" {
		t.Fatalf("bad row: %v %v %v %v %v %v", st, cls, tn, tf, rj, be)
	}
}

func TestMarkDoneDirectRequiresPending(t *testing.T) {
	// A submitted row is a live async task owned by a poller — a direct
	// verdict must not cut across the claim machinery.
	db, err := NewScanDB(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.UpsertPending("aa", "f", "a", 1)
	db.MarkSubmitted("aa", "u1")
	db.MarkDoneDirect("aa", "malicious", "T", nil, nil, "fie")
	if got := db.Counts()["submitted"]; got != 1 {
		t.Fatalf("submitted=%d, want 1", got)
	}
	if got := db.Counts()["done"]; got != 0 {
		t.Fatalf("done=%d, want 0", got)
	}
}

func TestResetSubmittedForBackend(t *testing.T) {
	// Rows in-flight under a different backend can never be polled by this
	// one — reset to pending. Same-backend (incl. legacy NULL='detect') and
	// terminal rows stay.
	db, err := NewScanDB(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.UpsertPending("aa", "f", "a", 1)
	db.MarkSubmitted("aa", "u1")
	db.q(`UPDATE uploads SET backend='a1000' WHERE sha256='aa'`)
	db.UpsertPending("bb", "f", "b", 1)
	db.MarkSubmitted("bb", "u2") // backend NULL -> 'detect'
	db.UpsertPending("cc", "f", "c", 1)
	db.MarkSubmitted("cc", "u3")
	db.ClaimReport("cc") // 'reporting' also resets
	db.q(`UPDATE uploads SET backend='fie' WHERE sha256='cc'`)
	db.UpsertPending("dd", "f", "d", 1)
	db.MarkSubmitted("dd", "u4")
	db.ClaimReport("dd")
	db.MarkDone("dd", "malicious", "", nil, nil)
	db.q(`UPDATE uploads SET backend='a1000' WHERE sha256='dd'`)

	db.ResetSubmittedForBackend("detect")
	c := db.Counts()
	if c["pending"] != 2 || c["submitted"] != 1 || c["done"] != 1 {
		t.Fatalf("counts=%v, want pending=2 submitted=1 done=1", c)
	}
	rows := db.qAll(`SELECT task_url FROM uploads WHERE sha256='aa'`)
	if rows == nil {
		t.Fatal("select failed")
	}
	defer rows.Close()
	if rows.Next() {
		var tu sql.NullString
		rows.Scan(&tu)
		if tu.Valid {
			t.Fatalf("task_url not cleared: %q", tu.String)
		}
	}
}

func newTestDB(t *testing.T) *ScanDB {
	t.Helper()
	db, err := NewScanDB(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestUpsertPendingRequeuesFailedAndTimeout(t *testing.T) {
	db := newTestDB(t)
	for _, st := range []string{"failed", "timeout"} {
		db.UpsertPending("aa", "f", "a", 1)
		db.q(`UPDATE uploads SET status=?, error='boom' WHERE sha256='aa'`, st)
		db.UpsertPending("aa", "f", "a", 1)
		if n := db.MarkDoneDirect("aa", "malicious", "T", nil, nil, "fie"); n != 1 {
			t.Fatalf("%s row: verdict not recorded (n=%d)", st, n)
		}
		db.q(`UPDATE uploads SET status='pending' WHERE sha256='aa'`)
	}
	db.q(`UPDATE uploads SET status='failed', error='x' WHERE sha256='aa'`)
	db.UpsertPending("aa", "f", "a", 1)
	v := db.Verdicts("")
	if len(v) != 1 || v[0].Status != "pending" || v[0].Error != "" {
		t.Fatalf("bad row %+v", v)
	}
}

func TestUpsertPendingLeavesInFlightAndDone(t *testing.T) {
	db := newTestDB(t)
	db.UpsertPending("aa", "f", "a", 1)
	db.MarkSubmitted("aa", "u")
	db.UpsertPending("aa", "f", "a", 1)
	if db.Counts()["submitted"] != 1 {
		t.Fatal("submitted row reset")
	}
	db.q(`UPDATE uploads SET status='done' WHERE sha256='aa'`)
	db.UpsertPending("aa", "f", "a", 1)
	if db.Counts()["done"] != 1 {
		t.Fatal("done row reset with resume on")
	}
	db.RescanDone = true
	db.UpsertPending("aa", "f", "a", 1)
	if db.Counts()["pending"] != 1 {
		t.Fatal("done row not re-queued with resume off")
	}
}

func TestMarkActionsAndVerdicts(t *testing.T) {
	db := newTestDB(t)
	db.UpsertPending("aa", "f", "a", 1)
	if v := db.Verdicts("")[0]; v.QuarantinedTo != "" || v.Alerted != nil {
		t.Fatalf("expected NULLs, got %+v", v)
	}
	db.MarkActions("aa", "/q/aa_f", true)
	v := db.Verdicts("")[0]
	if v.QuarantinedTo != "/q/aa_f" || v.Alerted == nil || *v.Alerted != 1 {
		t.Fatalf("bad %+v", v)
	}
}

func TestSchemaColumnOrder(t *testing.T) {
	db := newTestDB(t)
	rows := db.qAll(`SELECT name FROM pragma_table_info('uploads')`)
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		cols = append(cols, n)
	}
	n := len(cols)
	if n < 4 || cols[n-4] != "sha1" || cols[n-3] != "backend" ||
		cols[n-2] != "quarantined_to" || cols[n-1] != "alerted" {
		t.Fatalf("columns %v", cols)
	}
}

func TestMarkCachedBumpsUpdatedAt(t *testing.T) {
	db := newTestDB(t)
	db.UpsertPending("aa", "f", "a", 1)
	db.q(`UPDATE uploads SET status='done', updated_at='2000-01-01 00:00:00' WHERE sha256='aa'`)
	db.MarkCached("aa")
	rows := db.qAll(`SELECT updated_at FROM uploads WHERE sha256='aa'`)
	defer rows.Close()
	rows.Next()
	var u string
	rows.Scan(&u)
	if u < "2020" {
		t.Fatalf("updated_at not bumped: %s", u)
	}
}

// M9: a DB written by the previous release (sha1/backend present, no
// quarantined_to/alerted) gains the action columns, in schema order, and
// keeps its rows.
func TestScanDBMigratesHeadSchemaActionColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.db")
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Replace(oldUploadsSchema, "report_fetched_at TEXT\n",
		"report_fetched_at TEXT,\n    sha1 TEXT,\n    backend TEXT\n", 1)
	if _, err := conn.Exec(head); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO uploads(sha256,file_path,rel_path,
		file_size,status,classification,backend) VALUES('aa','f','r',1,'done','malicious','fie')`); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	db, err := NewScanDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := db.qAll(`SELECT name FROM pragma_table_info('uploads') ORDER BY cid`)
	var cols []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		cols = append(cols, n)
	}
	rows.Close()
	got := strings.Join(cols[len(cols)-4:], ",")
	if got != "sha1,backend,quarantined_to,alerted" {
		t.Fatalf("columns=%v", cols)
	}
	db.MarkActions("aa", "/q/aa", true)
	v := db.Verdicts("")
	if len(v) != 1 || v[0].Classification != "malicious" ||
		v[0].QuarantinedTo != "/q/aa" || v[0].Alerted == nil || *v[0].Alerted != 1 {
		t.Fatalf("verdicts=%+v", v)
	}
}

// R1: MarkFailed never clobbers a cached (or done/in-flight) row.
func TestMarkFailedKeepsCachedRow(t *testing.T) {
	db := newTestDB(t)
	db.UpsertPending("c", "/c", "c", 1)
	db.MarkCached("c")
	db.MarkFailed("c", nil, "max_in_flight throttle")
	if v := db.Verdicts(""); len(v) != 1 || v[0].Status != "cached" {
		t.Fatalf("verdicts=%+v", v)
	}
}

// M1/M2: startup resets, requeue and MarkActions do not bump updated_at —
// a row only enters a run's report once it records an outcome.
func TestResetsAndActionsKeepUpdatedAt(t *testing.T) {
	db := newTestDB(t)
	for _, s := range []string{"rep", "oth", "fail", "act"} {
		db.UpsertPending(s, "/"+s, s, 1)
	}
	db.MarkSubmitted("rep", "t1", "detect")
	db.ClaimReport("rep")
	db.MarkSubmitted("oth", "t2", "a1000")
	db.MarkFailed("fail", nil, "x")
	db.q(`UPDATE uploads SET updated_at='2000-01-01 00:00:00'`)
	db.ReclaimStaleReporting()
	db.ResetSubmittedForBackend("detect")
	db.UpsertPending("fail", "/fail2", "fail", 1) // requeue failed -> pending
	db.MarkActions("act", "/q/act", true)
	st := map[string]string{}
	for _, v := range db.Verdicts("") {
		st[v.Sha256] = v.Status
	}
	if st["rep"] != "submitted" || st["oth"] != "pending" || st["fail"] != "pending" {
		t.Fatalf("transitions=%v", st)
	}
	if n := len(db.Verdicts("2001-01-01 00:00:00")); n != 0 {
		t.Fatalf("%d row(s) had updated_at bumped", n)
	}
}
