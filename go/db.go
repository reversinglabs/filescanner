// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// db.go — ScanDB: SQLite-backed pipeline state, identical schema and
// transition rules to filescanner.py (resume-compatible).
package main

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const dbSchema = `
CREATE TABLE IF NOT EXISTS uploads(
    sha256 TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    file_size INTEGER,
    status TEXT NOT NULL DEFAULT 'pending',
    -- pending|submitted|reporting|failed|done|timeout|cached
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
    report_fetched_at TEXT,
    sha1 TEXT,
    backend TEXT,
    quarantined_to TEXT,
    alerted INTEGER
);
CREATE INDEX IF NOT EXISTS ix_status ON uploads(status);
`

type ScanDB struct {
	mu   sync.Mutex
	conn *sql.DB
	log  *Logger
	// RescanDone: when true (resume=false) UpsertPending also re-queues
	// 'done'/'cached' rows so a fresh verdict can be recorded.
	RescanDone bool
}

func NewScanDB(path string, lg ...*Logger) (*ScanDB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// Single connection + our own mutex: mirrors Python's check_same_thread
	// =False + lock, and keeps the UPDATE-based claim atomic.
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, err
	}
	if _, err := conn.Exec(dbSchema); err != nil {
		return nil, err
	}
	// Additive columns for multi-backend support. Fresh DBs already get them
	// from dbSchema, so the duplicate-column error is expected and ignored;
	// pre-existing DBs gain them here without losing rows.
	for _, col := range []string{"sha1 TEXT", "backend TEXT",
		"quarantined_to TEXT", "alerted INTEGER"} {
		if _, err := conn.Exec("ALTER TABLE uploads ADD COLUMN " + col); err != nil {
			if !strings.Contains(err.Error(), "duplicate column") {
				return nil, err
			}
		}
	}
	// q/qAll log errors rather than swallow them; a caller-supplied logger
	// wins, otherwise a plain stdout one so a failure always surfaces.
	l := newLogger(false, "", 0, 0)
	if len(lg) > 0 && lg[0] != nil {
		l = lg[0]
	}
	return &ScanDB{conn: conn, log: l}, nil
}

// q runs a write and returns rows-affected. A driver error is logged at
// ERROR (with the statement for context) and reported as 0 — a silent 0
// used to hide failed transitions entirely.
func (d *ScanDB) q(query string, args ...any) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(query, args...)
	if err != nil {
		d.log.Error("ScanDB exec failed: %v (sql: %.120s)", err, query)
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

func (d *ScanDB) qAll(query string, args ...any) *sql.Rows {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(query, args...)
	if err != nil {
		d.log.Error("ScanDB query failed: %v (sql: %.120s)", err, query)
		return nil
	}
	return rows // caller must read fully before next call (MaxOpenConns=1)
}

// UpsertPending registers/updates a pending row. sha1 is optional and
// additive (needs_sha1 backends); the COALESCE keeps an existing sha1 when
// a caller has none to give. A re-queued file's failed/timeout row (and
// done/cached when RescanDone) is reset to pending so MarkDoneDirect's
// status='pending' guard lets the fresh verdict land; in-flight
// (submitted/reporting) rows are never touched.
func (d *ScanDB) UpsertPending(sha, filePath, relPath string, size int64,
	sha1 ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.upsertPendingLocked(sha, filePath, relPath, size, sha1...)
}

// upsertPendingLocked is UpsertPending's body; caller holds d.mu.
func (d *ScanDB) upsertPendingLocked(sha, filePath, relPath string,
	size int64, sha1 ...string) {
	var s1 any
	if len(sha1) > 0 && sha1[0] != "" {
		s1 = sha1[0]
	}
	statuses := "'failed','timeout'"
	if d.RescanDone {
		statuses += ",'done','cached'"
	}
	// file_path/rel_path/file_size always track the latest seen path
	// EXCEPT on in-flight rows: pointing a 'submitted'/'reporting' row at
	// a duplicate's path would make the verdict's actions hit the wrong
	// file — MarkSubmittedPath stamps the submitter's path instead.
	// ('done'/'cached' rows DO update: the next run's cached-hit dedup
	// compares prior file_path against the scanned path.)
	if _, err := d.conn.Exec(`INSERT INTO uploads(sha256,file_path,rel_path,file_size,status,sha1)
	     VALUES(?,?,?,?,'pending',?)
	     ON CONFLICT(sha256) DO UPDATE SET
	         file_path=CASE WHEN uploads.status IN ('submitted','reporting')
	                  THEN uploads.file_path ELSE excluded.file_path END,
	         rel_path=CASE WHEN uploads.status IN ('submitted','reporting')
	                  THEN uploads.rel_path ELSE excluded.rel_path END,
	         file_size=CASE WHEN uploads.status IN ('submitted','reporting')
	                  THEN uploads.file_size ELSE excluded.file_size END,
	         sha1=COALESCE(excluded.sha1, uploads.sha1),
	         error=CASE WHEN uploads.status IN (`+statuses+`)
	                    THEN NULL ELSE uploads.error END,
	         http_status=CASE WHEN uploads.status IN (`+statuses+`)
	                    THEN NULL ELSE uploads.http_status END,
	         status=CASE WHEN uploads.status IN (`+statuses+`)
	                    THEN 'pending' ELSE uploads.status END`,
		sha, filePath, relPath, size, s1); err != nil {
		d.log.Error("ScanDB exec failed: %v (sql: upsert pending)", err)
	}
}

// PriorActions is a row's action state as it stood before an upsert:
// the path the row last pointed at plus the persisted quarantine/alert
// outcome (Alerted nil = never evaluated).
type PriorActions struct {
	FilePath, QuarantinedTo string
	Alerted                 *int64
}

// UpsertPendingPrior is UpsertPending that also returns the row's prior
// (file_path, quarantined_to, alerted) — read in the same critical section
// as the upsert so a concurrent duplicate at another path cannot slip in
// between. nil = no prior row. Cached-hit verdict actions compare the
// current path against this prior path (UpsertPending overwrites it).
func (d *ScanDB) UpsertPendingPrior(sha, filePath, relPath string,
	size int64, sha1 ...string) *PriorActions {
	d.mu.Lock()
	var prior *PriorActions
	rows, err := d.conn.Query(`SELECT file_path,quarantined_to,alerted
	                           FROM uploads WHERE sha256=?`, sha)
	if err != nil {
		d.log.Error("ScanDB query failed: %v (sql: prior actions)", err)
	} else {
		if rows.Next() {
			var qt sql.NullString
			var al sql.NullInt64
			var fp string
			if rows.Scan(&fp, &qt, &al) == nil {
				prior = &PriorActions{FilePath: fp, QuarantinedTo: qt.String}
				if al.Valid {
					prior.Alerted = &al.Int64
				}
			}
		}
		rows.Close()
	}
	d.upsertPendingLocked(sha, filePath, relPath, size, sha1...)
	d.mu.Unlock()
	return prior
}

type KnownVerdict struct {
	Classification string
	ThreatName     string
	ThreatFactor   *int64
	Status         string
}

func (d *ScanDB) KnownVerdict(sha string) *KnownVerdict {
	rows := d.qAll(`SELECT classification,threat_name,threat_factor,status
	                FROM uploads WHERE sha256=?
	                AND status IN ('done','submitted','reporting','cached')`, sha)
	if rows == nil {
		return nil
	}
	defer rows.Close()
	if !rows.Next() {
		return nil
	}
	var cls, tn sql.NullString
	var tf sql.NullInt64
	var st string
	rows.Scan(&cls, &tn, &tf, &st)
	kv := &KnownVerdict{Status: st}
	if cls.Valid {
		kv.Classification = cls.String
	}
	if tn.Valid {
		kv.ThreatName = tn.String
	}
	if tf.Valid {
		kv.ThreatFactor = &tf.Int64
	}
	return kv
}

// MarkSubmitted flips a row to 'submitted' with its receipt ref. backend is
// optional: when given it stamps which backend owns the receipt ref
// (COALESCE: empty leaves an existing stamp untouched — legacy callers stay
// neutral). Returns the UPDATE rowcount — 0 means the transition did not
// land (the driver error is logged by q), so the caller must not count a
// phantom submission.
func (d *ScanDB) MarkSubmitted(sha, taskURL string, backend ...string) int64 {
	return d.markSubmitted(sha, taskURL, "", "", backend...)
}

// MarkSubmittedPath is MarkSubmitted and also stamps the submitter's
// file_path/rel_path — the row always names the path that owns the
// in-flight task, never a duplicate's path.
func (d *ScanDB) MarkSubmittedPath(sha, taskURL, filePath, relPath string,
	backend ...string) int64 {
	return d.markSubmitted(sha, taskURL, filePath, relPath, backend...)
}

func (d *ScanDB) markSubmitted(sha, taskURL, filePath, relPath string,
	backend ...string) int64 {
	var be any
	if len(backend) > 0 && backend[0] != "" {
		be = backend[0]
	}
	return d.q(`UPDATE uploads SET status='submitted', task_url=?,
	     classification=NULL, threat_name=NULL, threat_factor=NULL,
	     report_json=NULL, error=NULL, http_status=NULL,
	     backend=COALESCE(?, backend),
	     file_path=COALESCE(NULLIF(?,''), file_path),
	     rel_path=COALESCE(NULLIF(?,''), rel_path),
	     uploaded_at=datetime('now'), updated_at=datetime('now'),
	     attempts=attempts+1 WHERE sha256=?`,
		taskURL, be, filePath, relPath, sha)
}

func truncErr(e string) string {
	if len(e) > 500 {
		return e[:500]
	}
	return e
}

func (d *ScanDB) MarkFailed(sha string, httpStatus *int, errStr string) {
	var hs any
	if httpStatus != nil {
		hs = *httpStatus
	}
	d.q(`UPDATE uploads SET status='failed', http_status=?, error=?,
	     updated_at=datetime('now') WHERE sha256=?
	     AND status NOT IN ('submitted','reporting','done','cached')`,
		hs, truncErr(errStr), sha)
}

func (d *ScanDB) FailClaimed(sha, errStr string) {
	d.q(`UPDATE uploads SET status='failed', error=?,
	     updated_at=datetime('now') WHERE sha256=? AND status='reporting'`,
		truncErr(errStr), sha)
}

// ClaimReport atomically flips submitted→reporting; true iff this caller won.
func (d *ScanDB) ClaimReport(sha string) bool {
	return d.q(`UPDATE uploads SET status='reporting',
	            updated_at=datetime('now')
	            WHERE sha256=? AND status='submitted'`, sha) == 1
}

func (d *ScanDB) UnclaimReport(sha string) {
	d.q(`UPDATE uploads SET status='submitted', updated_at=datetime('now')
	     WHERE sha256=? AND status='reporting'`, sha)
}

// ReclaimStaleReporting does not bump updated_at: a resumed row only enters
// this run's report once it records an outcome.
func (d *ScanDB) ReclaimStaleReporting() {
	d.q(`UPDATE uploads SET status='submitted' WHERE status='reporting'`)
}

type SubmittedRow struct{ Sha256, FilePath, RelPath, TaskURL string }

func (d *ScanDB) SubmittedRows() []SubmittedRow {
	rows := d.qAll(`SELECT sha256,file_path,rel_path,task_url FROM uploads
	                WHERE status IN ('submitted','reporting')`)
	if rows == nil {
		return nil
	}
	defer rows.Close()
	var out []SubmittedRow
	for rows.Next() {
		var r SubmittedRow
		var tu sql.NullString
		rows.Scan(&r.Sha256, &r.FilePath, &r.RelPath, &tu)
		r.TaskURL = tu.String
		out = append(out, r)
	}
	return out
}

// MarkDone completes a claimed ('reporting') row. Returns the UPDATE
// rowcount (like MarkDoneDirect) — 0 when the row left 'reporting' first
// (e.g. the deadline flipped it to 'timeout'), so the caller can skip the
// record + side effects that would wrongly mark a timed-out task completed.
func (d *ScanDB) MarkDone(sha, cls, threat string, factor *int64, reportJSON *string) int64 {
	var f, rj any
	if factor != nil {
		f = *factor
	}
	if reportJSON != nil {
		rj = *reportJSON
	}
	return d.q(`UPDATE uploads SET status='done', classification=?,
	     threat_name=?, threat_factor=?, report_json=?,
	     report_fetched_at=datetime('now'), updated_at=datetime('now')
	     WHERE sha256=? AND status='reporting'`, cls, threat, f, rj, sha)
}

// MarkDoneDirect: synchronous verdict with no submit/poll round-trip
// (FIE /scan, reputation pre-check) — pending -> done, stamping backend.
// Returns the UPDATE rowcount (1 iff a 'pending' row actually flipped) so a
// caller can tell its verdict landed without a second query.
func (d *ScanDB) MarkDoneDirect(sha, cls, threat string, factor *int64, reportJSON *string, backend string) int64 {
	var f, rj any
	if factor != nil {
		f = *factor
	}
	if reportJSON != nil {
		rj = *reportJSON
	}
	return d.q(`UPDATE uploads SET status='done', classification=?,
	     threat_name=?, threat_factor=?, report_json=?, backend=?,
	     report_fetched_at=datetime('now'), updated_at=datetime('now')
	     WHERE sha256=? AND status='pending'`, cls, threat, f, rj, backend, sha)
}

// ResetSubmittedForBackend: startup resume — 'submitted'/'reporting' rows
// owned by a different backend can never be polled by this one (receipt refs
// are backend-specific), so hand them back to 'pending'. Legacy rows have
// backend=NULL, which reads as 'detect'. task_url is cleared — it is the
// other backend's stale receipt ref.
func (d *ScanDB) ResetSubmittedForBackend(current string) {
	d.q(`UPDATE uploads SET status='pending', task_url=NULL
	     WHERE status IN ('submitted','reporting')
	     AND COALESCE(backend,'detect') != ?`, current)
}

func (d *ScanDB) MarkCached(sha string) {
	d.q(`UPDATE uploads SET status='cached', updated_at=datetime('now')
	     WHERE sha256=?`, sha)
}

// MarkActions persists the outcome of verdict actions: the quarantine
// destination ("" = none, stored NULL) and whether an alert fired (0/1).
func (d *ScanDB) MarkActions(sha, quarantinedTo string, alerted bool) {
	var q any
	if quarantinedTo != "" {
		q = quarantinedTo
	}
	a := 0
	if alerted {
		a = 1
	}
	d.q(`UPDATE uploads SET quarantined_to=?, alerted=? WHERE sha256=?`,
		q, a, sha)
}

// TimeoutExpired flips every in-flight row whose own report wait ran out
// (now > max(uploaded_at, runStartedAt) + waitSec; legacy NULL uploaded_at
// falls back to created_at) to 'timeout' and returns how many flipped.
// Per-row deadline: a file uploaded late in the run gets its full wait too,
// and a row resumed from an earlier run gets waitSec counted from this
// run's start (runStartedAt, SQLite datetime('now') text; "" = no floor).
func (d *ScanDB) TimeoutExpired(waitSec int64, runStartedAt string) int64 {
	return d.q(`UPDATE uploads SET status='timeout',
	            error='report wait exceeded', updated_at=datetime('now')
	            WHERE status IN ('submitted','reporting')
	            AND max(COALESCE(uploaded_at, created_at), ?) < datetime('now', ?)`,
		runStartedAt, fmt.Sprintf("-%d seconds", waitSec))
}

func (d *ScanDB) MarkReportTimeout(sha string) int64 {
	return d.q(`UPDATE uploads SET status='timeout', updated_at=datetime('now')
	            WHERE sha256=? AND status IN ('submitted','reporting')`, sha)
}

func (d *ScanDB) StaleErrorRows(before string) int {
	rows := d.qAll(`SELECT COUNT(*) FROM uploads
	                WHERE status IN ('failed','timeout') AND updated_at < ?
	                AND (error IS NULL OR error NOT LIKE 'skipped_filetype:%')`,
		before)
	if rows == nil {
		return 0
	}
	defer rows.Close()
	if rows.Next() {
		var n int
		rows.Scan(&n)
		return n
	}
	return 0
}

func (d *ScanDB) Counts() map[string]int {
	rows := d.qAll(`SELECT status, COUNT(*) FROM uploads GROUP BY status`)
	if rows == nil {
		return map[string]int{}
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		rows.Scan(&s, &n)
		out[s] = n
	}
	return out
}

func (d *ScanDB) InFlight() int {
	rows := d.qAll(`SELECT COUNT(*) FROM uploads
	                WHERE status IN ('submitted','reporting')`)
	if rows == nil {
		return 0
	}
	defer rows.Close()
	if rows.Next() {
		var n int
		rows.Scan(&n)
		return n
	}
	return 0
}

type FailedRow struct{ RelPath, Status, Error string }

func (d *ScanDB) FailedRows() []FailedRow {
	rows := d.qAll(`SELECT rel_path, status, error FROM uploads
	                WHERE status IN ('failed','timeout') ORDER BY rel_path`)
	if rows == nil {
		return nil
	}
	defer rows.Close()
	var out []FailedRow
	for rows.Next() {
		var r FailedRow
		var e sql.NullString
		rows.Scan(&r.RelPath, &r.Status, &e)
		r.Error = e.String
		out = append(out, r)
	}
	return out
}

func (d *ScanDB) OldRecords(days int) int {
	rows := d.qAll(`SELECT COUNT(*) FROM uploads WHERE created_at <
	                datetime('now', ?)`, fmt.Sprintf("-%d days", days))
	if rows == nil {
		return 0
	}
	defer rows.Close()
	if rows.Next() {
		var n int
		rows.Scan(&n)
		return n
	}
	return 0
}

func (d *ScanDB) DeleteOldRecords(days int) int64 {
	return d.q(`DELETE FROM uploads WHERE created_at < datetime('now', ?)`,
		fmt.Sprintf("-%d days", days))
}

type VerdictRow struct {
	Sha256, FilePath, RelPath, Status, Classification string
	ThreatName                                        string
	ThreatFactor                                      *int64
	ReportJSON                                        string
	Error                                             string
	HTTPStatus                                        *int64
	FileSize                                          int64
	Attempts                                          int64
	QuarantinedTo                                     string
	Alerted                                           *int64
}

// Now returns SQLite's UTC datetime('now') (same clock as updated_at).
func (d *ScanDB) Now() string {
	rows := d.qAll(`SELECT datetime('now')`)
	if rows == nil {
		return time.Now().UTC().Format("2006-01-02 15:04:05")
	}
	defer rows.Close()
	var s string
	if rows.Next() {
		rows.Scan(&s)
	}
	return s
}

// Verdicts returns rows with updated_at >= since ("" = all rows).
func (d *ScanDB) Verdicts(since string) []VerdictRow {
	rows := d.qAll(`SELECT sha256,file_path,rel_path,file_size,status,
	                classification,threat_name,threat_factor,report_json,
	                error,http_status,attempts,quarantined_to,alerted FROM uploads
	                WHERE ?='' OR updated_at >= ?`, since, since)
	if rows == nil {
		return nil
	}
	defer rows.Close()
	var out []VerdictRow
	for rows.Next() {
		var v VerdictRow
		var tn, cls, rj, er, qt sql.NullString
		var tf, hs, al sql.NullInt64
		rows.Scan(&v.Sha256, &v.FilePath, &v.RelPath, &v.FileSize, &v.Status,
			&cls, &tn, &tf, &rj, &er, &hs, &v.Attempts, &qt, &al)
		v.QuarantinedTo = qt.String
		if al.Valid {
			v.Alerted = &al.Int64
		}
		v.Classification = cls.String
		v.ThreatName = tn.String
		v.ReportJSON = rj.String
		v.Error = er.String
		if tf.Valid {
			v.ThreatFactor = &tf.Int64
		}
		if hs.Valid {
			v.HTTPStatus = &hs.Int64
		}
		out = append(out, v)
	}
	return out
}

func (d *ScanDB) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.conn.Close()
}
