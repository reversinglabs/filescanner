// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// scan.go — pipeline core: upload worker pool, result pollers, disk gate,
// cleanup prompt, run_scan orchestration. Mirrors filescanner.py semantics.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// ScanContext — shared state for workers/pollers.
// ---------------------------------------------------------------------------

type ScanContext struct {
	Args        *Args
	Counters    *Counters
	Locks       *KeyedLocks
	Alerter     *Alerter
	Quarantine  string
	Log         *Logger
	progMu      sync.Mutex
	Total       int
	doneUploads int
	doneReports int
	quarMu      sync.Mutex
	// dupPaths queues extra filesystem paths whose content shares a
	// hash-keyed uploads row owned by another path: verdict actions drain
	// it so every copy is quarantined, not just the row's file_path.
	dupMu    sync.Mutex
	dupPaths map[string][]dupPath
	// PollersGone is closed once every result poller has exited and Stop
	// once the run is cancelled; either releases a max_in_flight throttle
	// wait (nil = never). reportWait overrides report_wait_hours (tests).
	PollersGone <-chan struct{}
	Stop        <-chan struct{}
	reportWait  time.Duration
	// RunStartedAt (SQLite datetime('now') text) floors each in-flight
	// row's report-wait start, so rows resumed from an earlier run get a
	// full report_wait_hours from this run's start.
	RunStartedAt string
}

// reportWaitDur is the per-row report deadline: report_wait_hours unless a
// test overrides it.
func (c *ScanContext) reportWaitDur() time.Duration {
	if c.reportWait > 0 {
		return c.reportWait
	}
	return time.Duration(c.Args.ReportWaitHours) * time.Hour
}

// stopped reports whether the run was interrupted (first Ctrl-C).
func (c *ScanContext) stopped() bool {
	select {
	case <-c.Stop:
		return true
	default:
		return false
	}
}

func (c *ScanContext) AddTotal(n int) {
	c.progMu.Lock()
	c.Total += n
	c.progMu.Unlock()
}

// dupPath is one extra filesystem path whose content shares a hash-keyed
// uploads row owned by another path.
type dupPath struct {
	Abs, Rel string
}

// NoteDupPath queues abs/rel under sha for the verdict's per-path drain.
func (c *ScanContext) NoteDupPath(sha, abs, rel string) {
	c.dupMu.Lock()
	defer c.dupMu.Unlock()
	if c.dupPaths == nil {
		c.dupPaths = map[string][]dupPath{}
	}
	c.dupPaths[sha] = append(c.dupPaths[sha], dupPath{Abs: abs, Rel: rel})
}

// TakeDupPaths pops every queued duplicate path (drain is one-shot).
func (c *ScanContext) TakeDupPaths(sha string) []dupPath {
	c.dupMu.Lock()
	defer c.dupMu.Unlock()
	d := c.dupPaths[sha]
	delete(c.dupPaths, sha)
	return d
}

func (c *ScanContext) every() int {
	if c.Args.ProgressEvery > 0 {
		return c.Args.ProgressEvery
	}
	return 100
}

func (c *ScanContext) BumpProgress(rel, note string, ok bool) {
	c.progMu.Lock()
	c.doneReports++
	done, total := c.doneReports, c.Total
	c.progMu.Unlock()
	if ok {
		c.Log.Debug("[report %d/%d] %s %s", done, total, note, rel)
		if done%c.every() == 0 {
			c.Log.Info("progress reports: %d/%d collected", done, total)
		}
	} else {
		c.Log.Warn("[report %d/%d] %s %s", done, total, note, rel)
	}
}

func (c *ScanContext) BumpUpload(rel, note string, ok bool) {
	c.progMu.Lock()
	c.doneUploads++
	done, total := c.doneUploads, c.Total
	c.progMu.Unlock()
	if ok {
		c.Log.Debug("[upload %d/%d] %s %s", done, total, note, rel)
		if done%c.every() == 0 {
			s := c.Counters.Snapshot()
			c.Log.Info("progress uploads: %d/%d done "+
				"(submitted=%d cached=%d failed=%d skipped=%d)",
				done, total, s["submitted"], s["cached"], s["errors"],
				s["skipped_filetype"])
		}
	} else {
		c.Log.Warn("[upload %d/%d] %s %s", done, total, note, rel)
	}
}

// ---------------------------------------------------------------------------
// Upload workers
// ---------------------------------------------------------------------------

// uploadWorker drains workQ: hash+head in one pass, dedup, submit via the
// ScanBackend, record in DB. workQ items are precheckItems: Raw=true items
// come straight from the feed loop (unhashed); prehashed dicts come back
// from the precheck stage and skip readHashCapture. With precheckQ set,
// hashed items detour through the reputation pre-check instead of being
// submitted. feedWG tracks Raw-item completion so the pool can tell when
// the raw feed is fully hashed (precheck shutdown ordering). Channel close
// is the sentinel (same as before); a failure on one item is logged/counted
// and never kills the worker.
func uploadWorker(ctx *ScanContext, db *ScanDB, backend ScanBackend,
	workQ <-chan precheckItem, precheckQ chan<- precheckItem,
	feedWG *sync.WaitGroup, writer *ResultsWriter) {
	a := ctx.Args
	for item := range workQ {
		func() { // per-item panic isolation, mirroring the broad except
			var sha256, sha1 string
			filePath, relPath := item.AbsPath, item.RelPath
			defer func() {
				if item.Raw {
					feedWG.Done()
				}
				if r := recover(); r != nil {
					ctx.Counters.Inc("errors", 1)
					ctx.Log.Error("Upload worker error on %s: %v",
						relPath, r)
					key := sha256
					if key == "" {
						key = "nohash:" + relPath
						db.UpsertPending(key, filePath, relPath, 0)
					}
					db.MarkFailed(key, nil,
						fmt.Sprintf("worker_error: %v", r))
				}
			}()
			if ctx.stopped() {
				return // interrupted: drain without starting new work
			}

			var head []byte
			var fileSize int64
			var prior *PriorActions // row state before this upsert (C2)
			if item.Prehashed && item.Sha256 != "" {
				// Re-enqueued by the precheck stage — hashes/head/size
				// carried along; skip a second read pass.
				sha256 = item.Sha256
				sha1 = item.Sha1
				head = item.Head
				fileSize = item.Size
				prior = db.UpsertPendingPrior(sha256, filePath, relPath,
					fileSize, sha1)
			} else {
				if st, err := os.Stat(filePath); err == nil {
					fileSize = st.Size()
				}
				// One streaming pass: sha256 (+sha1 for needs_sha1
				// backends) of the whole file + the head bytes the
				// file_types filter inspects (see headCaptureBytes).
				sha256, sha1, head, _ = readHashCapture(filePath,
					headCaptureBytes(a, fileSize), backend.NeedsSHA1())
				if sha256 == "" {
					key := "nohash:" + relPath
					db.UpsertPending(key, filePath, relPath, fileSize)
					db.MarkFailed(key, nil, "read_error")
					ctx.Counters.Inc("errors", 1)
					ctx.BumpUpload(relPath, "READ-ERROR", false)
					return
				}
				prior = db.UpsertPendingPrior(sha256, filePath, relPath,
					fileSize, sha1)
			}

			// Dedup-check + submit is check-then-act: serialize per sha256.
			lk := ctx.Locks.Get(sha256)
			lk.Lock()
			defer lk.Unlock()

			known := db.KnownVerdict(sha256)
			if known != nil && (known.Status == "submitted" || known.Status == "reporting") {
				ctx.Counters.Inc("cached", 1)
				ctx.BumpUpload(relPath, "ALREADY-SUBMITTED", true)
				// The row is owned by another path but the verdict's
				// actions apply to every copy of this content.
				parkDupPath(ctx, db, backend.Name(), sha256,
					filePath, relPath, writer)
				return
			}
			if a.Resume && known != nil &&
				(known.Status == "done" || known.Status == "cached") {
				db.MarkCached(sha256)
				ctx.Counters.Inc("cached", 1)
				cachedVerdictActions(ctx, db, backend, known, prior,
					sha256, filePath, relPath, writer)
				ctx.BumpUpload(relPath, "CACHED", true)
				return
			}

			if len(a.FileTypesSet) > 0 {
				ftype := detectFileType(head[:min(HeadCaptureBytes, len(head))])
				if !a.FileTypesSet[ftype] {
					db.MarkFailed(sha256, nil, "skipped_filetype:"+ftype)
					ctx.Counters.Inc("skipped_filetype", 1)
					ctx.BumpUpload(relPath, "SKIP (file-type)", true)
					return
				}
			}

			if precheckQ != nil && item.Raw {
				// Reputation pre-check stage: hand the freshly-hashed
				// item off — non-blocking send -> no deadlock under the
				// keyed lock. A saturated stage fails open the same way
				// a bulk error does: fall through to the inline submit
				// below (every local is already populated). Verdicts
				// land there; unknowns come back with Raw=false and take
				// the submit path (re-diverting them would bounce the
				// file between the two queues forever).
				select {
				case precheckQ <- precheckItem{
					Sha256: sha256, Sha1: sha1, AbsPath: filePath,
					RelPath: relPath, Size: fileSize, Head: head,
					Prehashed: true}:
					return
				default:
					ctx.Counters.Inc("precheck_bypassed", 1)
				}
			}

			// Don't overwhelm Detect: throttle when too many in flight.
			// Pollers drain InFlight (verdicts or per-row timeouts); if they
			// are gone or the run is stopped nothing ever will — give up on
			// this item instead of spinning forever.
			for a.MaxInFlight > 0 && db.InFlight() >= a.MaxInFlight {
				if !throttleWait(ctx) {
					if ctx.stopped() {
						// Ctrl-C: leave the row pending for the next
						// resume — not a failure (Python parity).
						return
					}
					db.MarkFailed(sha256, nil, throttleAbortErr)
					ctx.Counters.Inc("errors", 1)
					ctx.BumpUpload(relPath, "FAILED throttle", false)
					return
				}
			}

			meta := map[string]any{
				"original_relative_path": relPath,
				"original_absolute_path": filePath,
				"sha256":                 sha256,
				"rel_path":               relPath,
			}
			outcome := backend.SubmitWithBackoff(
				filePath, sha256, sha1, meta, a, ctx.Log)
			switch outcome.Kind {
			case "receipt":
				if db.MarkSubmittedPath(sha256, outcome.Ref, filePath,
					relPath, backend.Name()) > 0 {
					ctx.Counters.Inc("submitted", 1)
					ctx.BumpUpload(relPath,
						fmt.Sprintf("SUBMITTED [%s]", backend.Name()), true)
				} else {
					// The UPDATE did not land (driver error already
					// logged by ScanDB) — an untracked live task is an
					// error, not a submission.
					ctx.Counters.Inc("errors", 1)
					ctx.BumpUpload(relPath, "FAILED db", false)
				}
			case "verdict":
				// Synchronous verdict (FIE): pending -> done directly,
				// then the same side effects the result poller applies.
				var rj *string
				if a.StoreFullReport {
					rj = outcome.ReportJSON
				}
				cls := "unknown"
				if outcome.Classification != nil {
					cls = *outcome.Classification
				}
				threat := ""
				if outcome.ThreatName != nil {
					threat = *outcome.ThreatName
				}
				if db.MarkDoneDirect(sha256, cls, threat,
					outcome.ThreatFactor, rj, backend.Name()) > 0 {
					var report any
					if outcome.ReportJSON != nil {
						_ = json.Unmarshal([]byte(*outcome.ReportJSON),
							&report)
					}
					record := map[string]any{
						"file_path":      relPath,
						"absolute_path":  filePath,
						"file_type":      nil,
						"sha256":         sha256,
						"classification": cls,
						"threat_name":    outcome.ThreatName,
						"threat_factor":  outcome.ThreatFactor,
						"task_url":       nil,
						"quarantined_to": nil,
						"alerted":        false,
						"api": map[string]any{
							"status": "completed", "error": nil,
							"report": reportUnless(a.SummaryOnly, report),
						},
					}
					if backend.Name() != "detect" {
						record["backend"] = backend.Name()
					}
					verdictActions(ctx, db, record, writer)
					if writer != nil {
						writer.Write(record)
					}
					ctx.BumpUpload(relPath,
						strings.ToUpper(cls)+" (sync)", true)
				} else {
					// Row was not 'pending' — another path owns it now
					// (dup content / resumed run). Queue this path so
					// its verdict's actions still reach every copy.
					ctx.Counters.Inc("cached", 1)
					ctx.BumpUpload(relPath, "CACHED", true)
					parkDupPath(ctx, db, backend.Name(), sha256,
						filePath, relPath, writer)
				}
			default: // "error"
				errStr := ""
				if outcome.Error != nil {
					errStr = *outcome.Error
				}
				db.MarkFailed(sha256, outcome.HTTPStatus, errStr)
				ctx.Counters.Inc("errors", 1)
				hs := 0
				if outcome.HTTPStatus != nil {
					hs = *outcome.HTTPStatus
				}
				ctx.BumpUpload(relPath,
					fmt.Sprintf("FAILED %d", hs), false)
			}
		}()
	}
}

// headCaptureBytes: the head is consumed only by the file_types filter,
// which reads head[:HeadCaptureBytes] — capture nothing else (extract_* and
// DetectFileType alone have no head consumer).
func headCaptureBytes(a *Args, fileSize int64) int {
	if len(a.FileTypesSet) == 0 {
		return 0
	}
	return int(min64(fileSize, HeadCaptureBytes))
}

const throttleAbortErr = "max_in_flight throttle: result pollers stopped"

// throttleWait sleeps one poll interval; false = stop waiting (pollers gone
// or run stopped).
func throttleWait(ctx *ScanContext) bool {
	select {
	case <-ctx.PollersGone:
		return false
	case <-ctx.Stop:
		return false
	case <-time.After(time.Duration(
		max(1, ctx.Args.ResultPollInterval)) * time.Second):
		return true
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// runUploadPool feeds items through a bounded channel; the channel cap
// back-pressures the lazy walk. Returns the number fed.
//
// With precheckClient set, one precheckWorker runs alongside the upload
// workers: hashed items detour through precheckQ for a TCA-0101 verdict and
// unknowns come back as prehashed dicts. Shutdown is ordered — feedWG drains
// the raw feed (every item hashed), closing precheckQ flushes the precheck
// stage (preWG.Wait guarantees every re-enqueue is already on workQ), then
// workQ closes so workers finish all remaining dicts before exiting. No file
// is stranded and no worker exits early.
func runUploadPool(ctx *ScanContext, db *ScanDB, backend ScanBackend,
	workIter <-chan workItem, writer *ResultsWriter,
	precheckClient *TicloudClient) int {
	workQ := make(chan precheckItem, max(4, 4*ctx.Args.UploadWorkers))
	var precheckQ chan precheckItem
	var preWG sync.WaitGroup
	if precheckClient != nil {
		precheckQ = make(chan precheckItem,
			max(4, 4*ctx.Args.UploadWorkers))
		preWG.Add(1)
		go func() {
			defer preWG.Done()
			precheckWorker(ctx, db, precheckClient, precheckQ, workQ,
				writer)
		}()
	}
	var feedWG sync.WaitGroup
	var wg sync.WaitGroup
	for i := 0; i < ctx.Args.UploadWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			uploadWorker(ctx, db, backend, workQ, precheckQ, &feedWG,
				writer)
		}()
	}
	fed := 0
	for item := range workIter {
		if ctx.stopped() {
			break // interrupted: stop feeding new files
		}
		feedWG.Add(1)
		workQ <- precheckItem{AbsPath: item.AbsPath,
			RelPath: item.RelPath, Raw: true}
		fed++
		ctx.AddTotal(1)
	}
	if precheckQ != nil {
		feedWG.Wait()    // every raw item hashed -> precheck fed
		close(precheckQ) // drain + flush the precheck stage
		preWG.Wait()     // all unknowns re-enqueued onto workQ
	}
	close(workQ) // channel close = per-worker sentinel
	wg.Wait()
	return fed
}

// ---------------------------------------------------------------------------
// Result poller — claim/poll/apply, TaskGone → terminal failure.
// ---------------------------------------------------------------------------

// pollIteration is one pass over the submitted rows; returns true when the
// poller should exit: uploads finished AND no submitted/reporting rows
// remain. The report wait is a per-row deadline (uploaded_at +
// report_wait_hours) — expired rows flip to 'timeout' every pass; it is
// never a poller exit condition, so a late upload still gets polled.
//
// ScanBackend path: claim a batch of submitted rows (submitted->reporting is
// atomic per row, so >1 poller can never apply side effects twice), then one
// PollBatch resolves them — "gone" -> FailClaimed (detect task-eviction
// parity), "pending"/missing -> UnclaimReport, a verdict map -> MarkDone +
// record + verdictActions.
func pollIteration(ctx *ScanContext, db *ScanDB, backend ScanBackend,
	uploadsDone <-chan struct{}, writer *ResultsWriter,
	seenStuck *time.Time) (done bool) {
	defer func() {
		if r := recover(); r != nil {
			ctx.Log.Error("result poller error (continuing): %v", r)
			time.Sleep(time.Duration(max(1, ctx.Args.ResultPollInterval)) * time.Second)
		}
	}()
	a := ctx.Args
	if n := db.TimeoutExpired(int64(ctx.reportWaitDur()/time.Second),
		ctx.RunStartedAt); n > 0 {
		ctx.Counters.Inc("errors", int(n))
		ctx.Log.Warn("Report wait exceeded; %d row(s) timed out", n)
	}
	rows := db.SubmittedRows()
	var claimed []SubmittedRow
	var refs []PollRef
	for _, row := range rows {
		if db.ClaimReport(row.Sha256) {
			claimed = append(claimed, row)
			refs = append(refs, PollRef{Ref: row.TaskURL, Sha256: row.Sha256})
		}
	}
	var results map[string]any
	if len(refs) > 0 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Transient sweep failure — claims release below.
					ctx.Log.Warn("report poll_batch failed: %v", r)
					results = nil
				}
			}()
			results = backend.PollBatch(refs)
		}()
	}
	for _, row := range claimed {
		res, ok := results[row.TaskURL]
		if !ok || res == nil {
			db.UnclaimReport(row.Sha256) // missing result -> retry next sweep
			continue
		}
		if s, isStr := res.(string); isStr {
			if s == "gone" {
				// Receipt purged server-side — terminal, not retriable.
				db.FailClaimed(row.Sha256, "task record lost (404)")
				ctx.Counters.Inc("errors", 1)
				ctx.Log.Warn("task record gone (404), marked failed: %s",
					row.RelPath)
			} else {
				db.UnclaimReport(row.Sha256) // "pending"/unknown
			}
			continue
		}
		vmap, isMap := res.(map[string]any)
		if !isMap {
			db.UnclaimReport(row.Sha256) // unexpected value -> retry
			continue
		}
		cls, _ := vmap["classification"].(string)
		if cls == "" {
			cls = "unknown"
		}
		threat, _ := vmap["threat_name"].(string)
		factor, _ := vmap["threat_factor"].(*int64)
		report := vmap["report_json"]
		var reportJSON *string
		if a.StoreFullReport && report != nil {
			if b, err := json.Marshal(report); err == nil {
				s := string(b)
				reportJSON = &s
			}
		}
		if db.MarkDone(row.Sha256, cls, threat, factor, reportJSON) == 0 {
			// Deadline/claim race: the row left 'reporting' (e.g. flipped
			// to 'timeout') between claim and now — writing a "completed"
			// record + quarantine/alert would be wrong for it.
			continue
		}
		record := map[string]any{
			"file_path":      row.RelPath,
			"absolute_path":  row.FilePath,
			"file_type":      nil,
			"sha256":         row.Sha256,
			"classification": cls,
			"threat_name":    vmap["threat_name"],
			"threat_factor":  factor,
			"task_url":       row.TaskURL,
			"quarantined_to": nil,
			"alerted":        false,
			"api": map[string]any{
				"status": "completed", "error": nil,
				"report": reportUnless(a.SummaryOnly, report),
			},
		}
		if backend.Name() != "detect" {
			record["backend"] = backend.Name()
		}
		if rmap, isRMap := report.(map[string]any); isRMap {
			if ind := extractReportIndicators(rmap, 200); len(ind) > 0 {
				record["spectra_report_indicators"] = ind
			}
		}
		verdictActions(ctx, db, record, writer)
		writer.Write(record)
		ctx.BumpProgress(row.RelPath, strings.ToUpper(cls), true)
	}
	if time.Since(*seenStuck) > 60*time.Second {
		*seenStuck = time.Now()
		ctx.Log.Info("progress: uploads %v | reports pending=%d",
			db.Counts(), db.InFlight())
	}
	select {
	case <-uploadsDone:
		if len(db.SubmittedRows()) == 0 {
			return true
		}
	default:
	}
	select {
	case <-ctx.Stop: // interrupted: exit promptly, rows stay submitted
		return true
	case <-time.After(time.Duration(max(1, a.ResultPollInterval)) * time.Second):
	}
	return false
}

func resultPoller(ctx *ScanContext, db *ScanDB, backend ScanBackend,
	uploadsDone <-chan struct{}, writer *ResultsWriter) {
	seenStuck := time.Now().Add(-61 * time.Second) // first heartbeat immediate
	for !ctx.stopped() {
		if pollIteration(ctx, db, backend, uploadsDone, writer,
			&seenStuck) {
			return
		}
	}
}

// processed returns the task's processed timestamp (0/nil/false = still
// running) — mirrors python task.get("processed") in (None, 0) where
// False == 0.
func processed(task map[string]any) float64 {
	switch v := task["processed"].(type) {
	case float64:
		return v
	case bool:
		if v {
			return 1
		}
		return 0
	case nil:
		return 0
	default:
		return 1 // truthy non-numeric — treat as processed
	}
}

func reportUnless(summaryOnly bool, report any) any {
	if summaryOnly {
		return nil
	}
	return report
}

func verdictActions(ctx *ScanContext, db *ScanDB, record map[string]any,
	writer *ResultsWriter) {
	cls, _ := record["classification"].(string)
	if cls == "malicious" || cls == "suspicious" || cls == "goodware" || cls == "unknown" {
		ctx.Counters.Inc(cls, 1)
	} else {
		ctx.Counters.Inc("other", 1)
	}
	applyActions(ctx, db, record, true, true)
	// Every in-run duplicate path queued behind this verdict gets the same
	// per-path treatment; the hash's alert stays single.
	sha, _ := record["sha256"].(string)
	abs0, _ := record["absolute_path"].(string)
	be, _ := record["backend"].(string)
	for _, dp := range ctx.TakeDupPaths(sha) {
		if dp.Abs == abs0 {
			continue // the row's own path — actioned above
		}
		applyDupPath(ctx, sha, cls, record["threat_name"],
			record["threat_factor"], be, dp, writer)
	}
}

// applyDupPath runs verdict side effects + emits an NDJSON row for ONE
// duplicate path of a hash whose verdict already landed. Quarantine runs
// per path (each physical copy); the alert stays per-hash — the primary
// record's alert fired already. The row keeps its single file_path.
func applyDupPath(ctx *ScanContext, sha, cls string, threat, factor any,
	backendName string, dp dupPath, writer *ResultsWriter) {
	if cls == "" {
		cls = "unknown"
	}
	record := map[string]any{
		"file_path":      dp.Rel,
		"absolute_path":  dp.Abs,
		"file_type":      nil,
		"sha256":         sha,
		"classification": cls,
		"threat_name":    threat,
		"threat_factor":  factor,
		"task_url":       nil,
		"quarantined_to": nil,
		"alerted":        false,
		"duplicate":      true,
		"cached":         true,
		"api": map[string]any{
			"status": "cached", "error": nil, "report": nil,
		},
	}
	if backendName != "" && backendName != "detect" {
		record["backend"] = backendName
	}
	if cls == "malicious" || cls == "suspicious" || cls == "goodware" || cls == "unknown" {
		ctx.Counters.Inc(cls, 1)
	} else {
		ctx.Counters.Inc("other", 1)
	}
	a := ctx.Args
	if a.QuarantineOn[cls] && a.QuarantineAction != "none" {
		ctx.quarMu.Lock() // same atomic check-then-act as verdictActions
		dest := quarantineFile(dp.Abs, sha, cls, ctx.Quarantine,
			a.QuarantineAction, ctx.Log)
		ctx.quarMu.Unlock()
		if dest != "" {
			record["quarantined_to"] = dest
			ctx.Counters.Inc("quarantined", 1)
		}
	}
	if writer != nil {
		writer.Write(record)
	}
	ctx.BumpUpload(dp.Rel, strings.ToUpper(cls)+" (dup)", true)
}

// parkDupPath queues this path for the verdict's per-path drain — or
// services every queued path right now if the verdict already landed
// between the dedup check and here (no drain is coming for late arrivals).
func parkDupPath(ctx *ScanContext, db *ScanDB, backendName, sha, abs, rel string,
	writer *ResultsWriter) {
	ctx.NoteDupPath(sha, abs, rel)
	kv := db.KnownVerdict(sha)
	if kv == nil || (kv.Status != "done" && kv.Status != "cached") {
		return
	}
	var threat any
	if kv.ThreatName != "" {
		threat = kv.ThreatName
	}
	for _, dp := range ctx.TakeDupPaths(sha) {
		applyDupPath(ctx, sha, kv.Classification, threat, kv.ThreatFactor,
			backendName, dp, writer)
	}
}

// applyActions runs quarantine (doQuar) and alert (doAlert) for record's
// classification, then persists quarantined_to/alerted via MarkActions.
// A skipped action keeps whatever record already carries.
func applyActions(ctx *ScanContext, db *ScanDB, record map[string]any,
	doQuar, doAlert bool) {
	a := ctx.Args
	cls, _ := record["classification"].(string)
	if doQuar && a.QuarantineOn[cls] && a.QuarantineAction != "none" {
		ctx.quarMu.Lock() // atomic check-then-act across pollers
		abs, _ := record["absolute_path"].(string)
		sha, _ := record["sha256"].(string)
		dest := quarantineFile(abs, sha, cls, ctx.Quarantine,
			a.QuarantineAction, ctx.Log)
		ctx.quarMu.Unlock()
		record["quarantined_to"] = dest
		if dest != "" {
			ctx.Counters.Inc("quarantined", 1)
		}
	}
	if doAlert && ctx.Alerter != nil && ctx.Alerter.MaybeAlert(record) {
		record["alerted"] = true
		ctx.Counters.Inc("alerts", 1)
	}
	sha, _ := record["sha256"].(string)
	qt, _ := record["quarantined_to"].(string)
	al, _ := record["alerted"].(bool)
	db.MarkActions(sha, qt, al)
}

// cachedVerdictActions: a resumed CACHED hit runs the same alert/quarantine
// side effects a fresh verdict would, unless the row's persisted actions
// show this same path was already handled (prior = row state captured
// before this file's upsert; the upsert overwrites file_path). Per action:
// quarantine is skipped iff same path && quarantined_to set; the alert iff
// same path && alerted=1. A duplicate at another path always acts. Emits
// the NDJSON record with "cached": true.
func cachedVerdictActions(ctx *ScanContext, db *ScanDB, backend ScanBackend,
	known *KnownVerdict, prior *PriorActions, sha256, filePath, relPath string,
	writer *ResultsWriter) {
	cls := known.Classification
	if cls == "" {
		cls = "unknown"
	}
	var threat any
	if known.ThreatName != "" {
		threat = known.ThreatName
	}
	record := map[string]any{
		"file_path":      relPath,
		"absolute_path":  filePath,
		"file_type":      nil,
		"sha256":         sha256,
		"classification": cls,
		"threat_name":    threat,
		"threat_factor":  known.ThreatFactor,
		"task_url":       nil,
		"quarantined_to": nil,
		"alerted":        false,
		"cached":         true,
		"api": map[string]any{
			"status": "cached", "error": nil, "report": nil,
		},
	}
	if backend.Name() != "detect" {
		record["backend"] = backend.Name()
	}
	quarDone, alertDone := false, false
	if prior != nil && prior.FilePath == filePath {
		if prior.QuarantinedTo != "" {
			quarDone = true
			record["quarantined_to"] = prior.QuarantinedTo
		}
		if prior.Alerted != nil && *prior.Alerted == 1 {
			alertDone = true
			record["alerted"] = true
		}
	}
	applyActions(ctx, db, record, !quarDone, !alertDone)
	if writer != nil {
		writer.Write(record)
	}
}

// ---------------------------------------------------------------------------
// Disk read gate
// ---------------------------------------------------------------------------

func diskReadGate(a *Args, work []workItem, log *Logger) {
	if a.ReadSpeedTest == "off" || len(work) == 0 {
		return
	}
	budget := int64(a.ReadTestMaxBytes)
	deadline := time.Now().Add(time.Duration(a.ReadTestMaxSec) * time.Second)
	start := time.Now()
	var read int64
	buf := make([]byte, 1<<20)
	for _, it := range work {
		if read >= budget || time.Now().After(deadline) {
			break
		}
		f, err := openRegular(it.AbsPath)
		if err != nil {
			continue
		}
		for read < budget && time.Now().Before(deadline) {
			n, rerr := f.Read(buf)
			read += int64(n)
			if rerr != nil {
				break
			}
		}
		f.Close()
	}
	elapsed := max(0.001, time.Since(start).Seconds())
	mbps := float64(read) / elapsed / 1_000_000
	log.Info("Disk read test: %.1f MB in %.1fs = %.2f MB/s",
		float64(read)/1_000_000, elapsed, mbps)
	if mbps >= float64(a.MinReadMbps) {
		return
	}
	msg := fmt.Sprintf("Disk read speed %.2f MB/s is below %d MB/s - "+
		"the drive will bottleneck scanning", mbps, a.MinReadMbps)
	if a.ReadSpeedTest == "always" {
		log.Error("%s (read_speed_test=always - aborting)", msg)
		os.Exit(1)
	}
	log.Warn("%s", msg)
	fmt.Print("Proceed anyway? [y/N] ")
	ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if s := strings.ToLower(strings.TrimSpace(ans)); s != "y" && s != "yes" {
		log.Error("Aborted: disk read test %.2f MB/s below threshold.", mbps)
		os.Exit(1)
	}
	log.Warn("Continuing despite slow disk read speed.")
}

// ---------------------------------------------------------------------------
// Startup retention prompt
// ---------------------------------------------------------------------------

func cleanupPrompt(db *ScanDB, a *Args, log *Logger) {
	old := db.OldRecords(a.RetentionDays)
	if old == 0 {
		return
	}
	switch a.CleanupOldRecords {
	case "never":
		log.Info("%d record(s) older than %d days kept (cleanup=never)",
			old, a.RetentionDays)
		return
	case "always":
		log.Info("Deleted %d old scan record(s)", db.DeleteOldRecords(a.RetentionDays))
	default: // ask
		fmt.Printf("%d scan record(s) older than %d days found. Delete them? [y/N] ",
			old, a.RetentionDays)
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if s := strings.ToLower(strings.TrimSpace(ans)); s == "y" || s == "yes" {
			log.Info("Deleted %d old scan record(s)", db.DeleteOldRecords(a.RetentionDays))
		}
	}
}

// ---------------------------------------------------------------------------
// run_scan orchestration
// ---------------------------------------------------------------------------

// newScanBackend is runScan's backend factory (a seam: tests inject a fake).
var newScanBackend = makeBackend

func runScan(a *Args, include map[string]bool, outputDir, runDir string,
	log *Logger, ic *interruptCtl) map[string]any {
	driveRoot := sanitizeDrivePath(a.Drive)
	log.Info("USB drive root: %s", driveRoot)
	if len(include) > 0 {
		log.Info("Extension filter: %d extensions (%s)",
			len(include), strings.Join(sortedKeys(include), ", "))
	} else {
		log.Info("No extension filter - ALL file types will be scanned")
	}
	if st, err := os.Stat(driveRoot); err != nil || !st.IsDir() {
		log.Error("Drive %s is not accessible. Is the USB mounted?", driveRoot)
		os.Exit(1)
	}

	// Backend construction probes auth-bearing services once — a bad token
	// must abort the run here, not surface as thousands of per-file upload
	// failures (makeBackend errors exit with code 2 like config failures).
	backend, berr := newScanBackend(a)
	if berr != nil {
		log.Error("%v", berr)
		os.Exit(2)
	}
	// Single-shot readyz can flap on a busy appliance; tolerate a ~30s blip.
	if !backend.WaitReady(30*time.Second, 5*time.Second, log) {
		log.Error("backend %q is not ready. Aborting.", backend.Name())
		os.Exit(1)
	}

	log.Info("Scanning drive (uploads start as files are discovered)...")
	workCh := make(chan workItem, 1024)
	go iterWorkItems(driveRoot, include, a.SkipHiddenDirs, workCh, log)

	// Disk gate samples the first items before any upload; buffered channel
	// keeps them in order — feed samples back through a prepended channel.
	sample := make([]workItem, 0, 256)
	for len(sample) < 256 {
		it, ok := <-workCh
		if !ok {
			break
		}
		sample = append(sample, it)
	}
	diskReadGate(a, sample, log)

	chained := make(chan workItem, 1024)
	go func() {
		defer close(chained)
		n := 0
		feed := func(it workItem) bool {
			if a.MaxFiles > 0 && n >= a.MaxFiles {
				return false
			}
			select {
			case chained <- it:
			case <-ic.stop: // Ctrl-C: stop walking/feeding new files
				return false
			}
			n++
			return true
		}
		for _, it := range sample {
			if !feed(it) {
				return
			}
		}
		for it := range workCh {
			if !feed(it) {
				return
			}
		}
	}()
	if a.MaxFiles > 0 {
		log.Info("File cap: max_files=%d", a.MaxFiles)
	}

	dbPath := a.DBPath
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(outputDir, dbPath)
	}
	db, err := NewScanDB(dbPath, log)
	if err != nil {
		log.Error("Cannot open state DB %s: %v", dbPath, err)
		os.Exit(1)
	}
	db.RescanDone = !a.Resume
	db.ReclaimStaleReporting() // claims from a killed run are unclaimable
	// In-flight rows owned by a different backend can never be polled by this
	// one — hand them back to 'pending' before any work begins.
	db.ResetSubmittedForBackend(backend.Name())
	cleanupPrompt(db, a, log)
	runStartedAt := db.Now() // run-scoped reports: updated_at >= this

	counters := NewCounters()
	quarDir := a.QuarantineDir
	if quarDir == "" {
		quarDir = filepath.Join(runDir, "quarantine")
	}

	var alerter *Alerter
	if len(a.AlertOn) > 0 {
		var syslogAddr *net.UDPAddr
		if a.AlertSyslog != "" {
			host, port, _ := strings.Cut(a.AlertSyslog, ":")
			pn := 514
			if port != "" {
				if v, err := strconv.Atoi(port); err == nil {
					pn = v
				} else {
					log.Warn("Invalid alert_syslog port %q; using 514.", port)
				}
			}
			if ip := net.ParseIP(host); ip != nil {
				syslogAddr = &net.UDPAddr{IP: ip, Port: pn}
			} else if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
				syslogAddr = &net.UDPAddr{IP: ips[0], Port: pn}
			} else {
				log.Warn("Cannot resolve alert_syslog host %q", host)
			}
		}
		alerter = NewAlerter(a.AlertOn, filepath.Join(runDir, AlertsFilename),
			a.AlertWebhook, syslogAddr, a.AlertEventlog, log)
	}

	ctx := &ScanContext{Args: a, Counters: counters, Locks: NewKeyedLocks(),
		Alerter: alerter, Quarantine: quarDir, Log: log, Stop: ic.stop,
		RunStartedAt: runStartedAt}

	// Synchronous backends (FIE) return verdicts on submit — no poll phase.
	nPollers := a.ResultPollers
	if nPollers < 1 {
		nPollers = 1
	}
	if backend.IsSync() {
		nPollers = 0
	}

	// Reputation pre-check is a separate TicloudClient (works with every
	// backend) — built only when enabled, and it fails fast on bad creds so
	// a typo'd password aborts the run instead of silently skipping.
	var precheckClient *TicloudClient
	if a.ReputationPrecheck {
		host := strings.TrimSpace(a.TicloudHost)
		user := strings.TrimSpace(a.TicloudUsername)
		pass := strings.TrimSpace(a.TicloudPassword)
		if host == "" || user == "" || pass == "" {
			log.Error("reputation.precheck=true requires ticloud.host, " +
				"ticloud.username and ticloud.password")
			os.Exit(2)
		}
		precheckClient = NewTicloudClient(host, user, pass,
			!a.NoVerifySSL, a.Proxy,
			time.Duration(a.TicloudUploadTimeout)*time.Second,
			time.Duration(a.TicloudMinIntervalMs)*time.Millisecond,
			a.TicloudExtended)
		if st, ok := precheckClient.probeStatus(8 * time.Second); ok &&
			ticloudAuthStatuses[st] {
			log.Error("ticloud rejected the configured credentials "+
				"(HTTP %d) — check ticloud.username/ticloud.password "+
				"or disable reputation.precheck", st)
			os.Exit(2)
		}
	}

	preNote := ""
	if precheckClient != nil {
		preNote = " +reputation-precheck"
	}
	log.Info("Submitting with %d upload worker(s), %d result poller(s) "+
		"[backend=%s]%s...", a.UploadWorkers, nPollers, backend.Name(),
		preNote)

	writer, err := NewResultsWriter(filepath.Join(runDir, "scan_results.ndjson"))
	if err != nil {
		log.Error("Cannot open scan_results.ndjson: %v", err)
		os.Exit(1)
	}
	uploadsDone := make(chan struct{})
	// Closed once every poller exits: releases a max_in_flight throttle
	// wait that could otherwise never drain (set before workers start).
	pollersGone := make(chan struct{})
	ctx.PollersGone = pollersGone

	var fedTotal atomic.Int64
	ic.live.Store(true) // from here a first Ctrl-C reports from DB state
	var poolWG sync.WaitGroup
	poolWG.Add(1)
	go func() {
		defer poolWG.Done()
		defer close(uploadsDone) // always release pollers, even on pool failure
		n := runUploadPool(ctx, db, backend, chained, writer,
			precheckClient)
		fedTotal.Store(int64(n))
		log.Info("Enumeration complete: %d files fed to upload workers.", n)
	}()

	var pollWG sync.WaitGroup
	for i := 0; i < nPollers; i++ {
		pollWG.Add(1)
		go func() {
			defer pollWG.Done()
			resultPoller(ctx, db, backend, uploadsDone, writer)
		}()
	}
	go func() { pollWG.Wait(); close(pollersGone) }()
	pipeDone := make(chan struct{})
	go func() { poolWG.Wait(); pollWG.Wait(); close(pipeDone) }()
	waitPipeline(pipeDone, ic.stop, interruptGrace, log)
	ic.live.Store(false) // Ctrl-C while reporting exits 130 (Python: uncaught)
	writer.Close()
	totalFiles := int(fedTotal.Load())

	if totalFiles == 0 && db.InFlight() == 0 && len(db.Counts()) == 0 {
		log.Warn("No files matched the specified extensions.")
		out := map[string]any{
			"scan_metadata": buildMetadata(a, driveRoot, 0, include),
			"summary":       map[string]any{},
			"results":       []any{},
		}
		db.Close()
		return out
	}

	sc := db.Counts()
	log.Info("OUTCOME uploads: submitted=%d cached=%d failed=%d | "+
		"reports: done=%d timeout=%d",
		sc["submitted"], sc["cached"], sc["failed"], sc["done"], sc["timeout"])
	for _, r := range db.FailedRows() {
		log.Warn("  FAIL %-50s %s: %.120s", r.RelPath, r.Status, r.Error)
	}

	defer db.Close()
	return buildOutputFromDB(a, db, counters, driveRoot, totalFiles,
		include, runStartedAt)
}
