// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// precheck.go — reputation pre-check worker (TCA-0101 bulk). Mirrors
// precheck_worker in filescanner.py: the stage sits between hashing and
// upload. Items arrive prehashed; non-UNKNOWN verdicts flip the pending row
// straight to 'done' (MarkDoneDirect, backend='ticloud') with the same
// NDJSON/counter/quarantine/alert side effects the result poller applies;
// UNKNOWN/unresolvable items re-enqueue onto workQ for the normal upload
// path — fail-open, never lost.
package main

import (
	"encoding/json"
	"strings"
	"time"
)

// precheckItem is the queue contract between the hashing stage, the precheck
// worker and the upload path — one shape on both channels, so items
// re-enqueue verbatim. Prehashed tells the upload worker to skip a second
// readHashCapture (the integration bead owns that branch). The hashing stage
// has already called UpsertPending for each item. Raw marks items that came
// straight from the pool's feed loop (unhashed) — runUploadPool counts their
// completions to know when the raw feed is fully hashed before closing
// precheckQ; re-enqueued items are never Raw.
type precheckItem struct {
	Sha256    string
	Sha1      string
	AbsPath   string
	RelPath   string
	Size      int64
	Head      []byte
	Prehashed bool
	Raw       bool
}

// precheckFlushInterval bounds how long a partial batch may wait for more
// items before flushing — a short tail must not stall the drain.
const precheckFlushInterval = 2 * time.Second

// reputationBulkWithBackoff wraps ReputationBulk in the same retry shape as
// ScanBackend.SubmitWithBackoff: every attempt gates on the shared
// availability cache (at most one probe per AvailProbeSeconds across
// workers); conn errors/timeouts/429/5xx stamp it unavailable so other
// callers gate instead of racing a sick service; retries back off
// exponentially inside UploadRetryWindow, bounded by MaxUploadAttempts.
// Non-retriable outcomes (auth 401/403, other 4xx, malformed body) return
// immediately — retrying them cannot help.
func reputationBulkWithBackoff(ctx *ScanContext, c *TicloudClient,
	hashes []string, a *Args) (int, []map[string]any, []any, string) {
	deadline := time.Now().Add(time.Duration(a.UploadRetryWindow) * time.Second)
	delay := time.Duration(max(1, a.BackoffBase)) * time.Second
	attempts := 0
	var lastStatus int
	var lastEntries []map[string]any
	var lastInvalid []any
	lastErr := "no attempt made"
	for attempts < a.MaxUploadAttempts {
		if !c.AvailableNow(
			time.Duration(a.AvailProbeSeconds) * time.Second) {
			ctx.Log.Warn("TiCloud not available — pausing reputation " +
				"pre-check")
			c.WaitReady(time.Duration(a.ReadyMaxWait)*time.Second,
				time.Duration(a.ReadyCheckInterval)*time.Second, ctx.Log)
		}
		attempts++
		lastStatus, lastEntries, lastInvalid, lastErr =
			c.ReputationBulk(hashes, "sha256")
		if lastErr == "" {
			return lastStatus, lastEntries, lastInvalid, ""
		}
		// conn error / saturation / server-side failure — gate all callers
		// on the shared cache instead of racing a sick service.
		if lastStatus == 0 || lastStatus == 429 || lastStatus >= 500 {
			c.MarkUnavailable()
		}
		retriable := lastStatus == 0 ||
			ticloudRetriableStatuses[lastStatus] || lastStatus >= 500
		if !retriable || !time.Now().Before(deadline) {
			break
		}
		if !c.WaitReady(time.Duration(a.ReadyMaxWait)*time.Second,
			time.Duration(a.ReadyCheckInterval)*time.Second, ctx.Log) {
			ctx.Log.Warn("readyz gate timed out after %ds; retrying anyway",
				a.ReadyMaxWait)
		}
		wait := delay
		if rem := time.Until(deadline); rem < wait {
			wait = max(0, rem)
		}
		ctx.Log.Warn("TiCloud reputation precheck attempt %d failed (%s); "+
			"retry in %.0fs", attempts, lastErr, wait.Seconds())
		time.Sleep(wait)
		delay *= 2
		if mx := time.Duration(a.BackoffMax) * time.Second; delay > mx {
			delay = mx
		}
	}
	return lastStatus, lastEntries, lastInvalid, lastErr
}

// precheckApplyBatch resolves one batch of sha256s via TCA-0101 and returns
// the items still needing the upload path — mirror of
// _precheck_apply_batch in filescanner.py:
//   - classification != "unknown" and the verdict lands (pending -> done):
//     MarkDoneDirect(backend='ticloud') + NDJSON record + counters/
//     quarantine/alert via verdictActions — the same side effects the result
//     poller applies. ReputationSkipClassified drops the item (never
//     uploaded); skip_classified=false re-enqueues it anyway (enrichment
//     mode).
//   - "unknown", missing entry, or a verdict that can't stick (the row is no
//     longer 'pending' — e.g. failed/timeout): returned for re-enqueue —
//     fail-open, the upload path must never lose a file. Rows already
//     in-flight ('submitted'/'reporting') are dropped instead — the live
//     task owns the row.
//   - bulk-call failure: every item returned for re-enqueue (fail-open).
//
// The caller (precheckWorker) owns the actual workQ send — a blocking send
// here could deadlock: upload workers block on a full precheckQ while this
// worker blocks on a full workQ. Returning items lets the worker keep
// receiving precheckQ while the re-enqueue drains.
func precheckApplyBatch(ctx *ScanContext, db *ScanDB, c *TicloudClient,
	items []precheckItem, writer *ResultsWriter,
	a *Args) []precheckItem {
	// Dedup preserves order; identical content shares one sha256 row.
	seen := make(map[string]bool, len(items))
	hashes := make([]string, 0, len(items))
	for _, it := range items {
		if !seen[it.Sha256] {
			seen[it.Sha256] = true
			hashes = append(hashes, it.Sha256)
		}
	}
	_, entries, invalid, errStr := reputationBulkWithBackoff(ctx, c, hashes, a)
	if errStr != "" {
		ctx.Counters.Inc("precheck_errors", 1)
		ctx.Log.Warn("reputation precheck failed (%s); %d item(s) "+
			"re-enqueued for upload", errStr, len(items))
		return items
	}
	if len(invalid) > 0 {
		ctx.Counters.Inc("precheck_invalid_hashes", len(invalid))
		ctx.Log.Warn("ticloud reputation precheck: %d invalid hash(es)",
			len(invalid))
	}
	// Extended entries echo the sample's hashes under sha1/md5/sha256 (mocks
	// may use hash_value) — same indexing as CloudBackend.PollBatch.
	byHash := map[string]map[string]any{}
	for _, e := range entries {
		for _, h := range ticloudEntryHashes(e) {
			if _, dup := byHash[h]; !dup {
				byHash[h] = e
			}
		}
	}
	var requeue []precheckItem
	for _, it := range items {
		ent := byHash[strings.ToLower(it.Sha256)]
		classified := false
		drop := false // in-flight rows are never re-enqueued
		if ent != nil {
			v := normalizeReputationEntry(ent)
			cls, _ := v["classification"].(string)
			if cls != "unknown" {
				classified = true
				// Hashing already UpsertPending'ed; repeating keeps the
				// worker safe if that contract drifts — the upsert never
				// touches status, so 'done'/'submitted' rows are untouched.
				// sha1 rides along so needs_sha1 backends keep their hash.
				db.UpsertPending(it.Sha256, it.AbsPath, it.RelPath, it.Size,
					it.Sha1)
				threat, _ := v["threat_name"].(string)
				factor, _ := v["threat_factor"].(*int64)
				// Same record shape resultPoller writes, plus the
				// backend marker.
				record := map[string]any{
					"file_path":      it.RelPath,
					"absolute_path":  it.AbsPath,
					"file_type":      nil,
					"sha256":         it.Sha256,
					"classification": cls,
					"threat_name":    v["threat_name"],
					"threat_factor":  factor,
					"task_url":       nil,
					"quarantined_to": nil,
					"alerted":        false,
					"backend":        "ticloud",
					"api": map[string]any{
						"status": "completed", "error": nil,
						"report": reportUnless(a.SummaryOnly, ent),
					},
				}
				flipped := false
				if a.ReputationSkipClassified {
					var rj *string
					if b, err := json.Marshal(v["raw"]); err == nil {
						s := string(b)
						rj = &s
					}
					flipped = db.MarkDoneDirect(it.Sha256, cls, threat,
						factor, rj, "ticloud") > 0
				}
				if flipped {
					verdictActions(ctx, db, record, writer)
					writer.Write(record)
					ctx.BumpProgress(it.RelPath,
						strings.ToUpper(cls)+" (precheck)", true)
				} else if !a.ReputationSkipClassified {
					// Enrichment only: the row stays 'pending' so the
					// upload path's resume dedup can't short-circuit —
					// the backend verdict owns the final row. No
					// quarantine or alerts yet: those are final-verdict
					// actions (a quarantine move would break the pending
					// upload, and alerting now would double-alert).
					writer.Write(record)
					ctx.BumpProgress(it.RelPath,
						strings.ToUpper(cls)+" (precheck)", true)
				} else {
					// The row was not 'pending': a verdict may already
					// stand (dup content, resumed run) or the row may be
					// unwritable ('failed'/'timeout' — never lose the
					// file).
					kv := db.KnownVerdict(it.Sha256)
					if kv != nil && (kv.Status == "submitted" ||
						kv.Status == "reporting") {
						// live task owns the row; its verdict's drain
						// still reaches this path.
						parkDupPath(ctx, db, "ticloud", it.Sha256,
							it.AbsPath, it.RelPath, writer)
						drop = true
					} else if kv == nil || (kv.Status != "done" &&
						kv.Status != "cached") {
						classified = false // verdict lost -> fail open
					} else {
						// Verdict already final: run per-path actions
						// for this copy now — no drain is coming.
						var threat any
						if kv.ThreatName != "" {
							threat = kv.ThreatName
						}
						applyDupPath(ctx, it.Sha256, kv.Classification,
							threat, kv.ThreatFactor, "ticloud",
							dupPath{Abs: it.AbsPath, Rel: it.RelPath},
							writer)
					}
				}
			}
		}
		if !drop && (!classified || !a.ReputationSkipClassified) {
			requeue = append(requeue, it)
		}
	}
	return requeue
}

// precheckWorker drains precheckQ in sha256 batches and resolves verdicts via
// TCA-0101 — mirror of precheck_worker in filescanner.py.
//
// Drain: collect up to ReputationBatchSize items; a timer flushes a partial
// batch precheckFlushInterval after its first item so a short tail never
// stalls. Closing precheckQ is the sentinel (same idiom as runUploadPool's
// close(workQ)) — the accumulated batch flushes before the worker returns,
// so queued files are never stranded. A panic mid-batch is contained
// (log + count) and fails open: every affected item is re-enqueued to workQ.
// Callers must keep workQ open until every precheck worker has returned.
//
// Deadlock freedom: re-enqueues never send to workQ directly. Items needing
// the upload path accumulate in `pending` and the select drains them onto
// workQ while still receiving precheckQ — a blocking send here plus upload
// workers blocked on a full precheckQ would lock the whole pool.
func precheckWorker(ctx *ScanContext, db *ScanDB, c *TicloudClient,
	precheckQ <-chan precheckItem, workQ chan<- precheckItem,
	writer *ResultsWriter) {
	a := ctx.Args
	batchSize := a.ReputationBatchSize
	if batchSize <= 0 {
		batchSize = ticloudReputationChunk // unset/0 = default (py `or 100`)
	}
	if batchSize > ticloudReputationChunk {
		batchSize = ticloudReputationChunk // API hard cap (also clamped in cfg)
	}
	var batch []precheckItem
	var pending []precheckItem // resolved items owed to the upload path
	timer := time.NewTimer(precheckFlushInterval)
	defer timer.Stop()

	flush := func() {
		items := batch
		batch = nil
		if len(items) == 0 {
			return
		}
		defer func() {
			if r := recover(); r != nil {
				// Fail-open: never lose files — route the whole batch to
				// the upload path.
				ctx.Counters.Inc("precheck_errors", 1)
				ctx.Log.Error("precheck batch failed; re-enqueueing %d "+
					"item(s): %v", len(items), r)
				pending = append(pending, items...)
			}
		}()
		pending = append(pending,
			precheckApplyBatch(ctx, db, c, items, writer, a)...)
	}

	for {
		// Select-case channels must be built before select: a nil workOut
		// disables the workQ send while pending is empty.
		var workOut chan<- precheckItem
		var next precheckItem
		if len(pending) > 0 {
			workOut = workQ
			next = pending[0]
		}
		select {
		case item, ok := <-precheckQ:
			if !ok {
				// Channel closed = sentinel: feed finished — drain, exit.
				flush()
				for _, it := range pending {
					workQ <- it // workers still consume; safe to block
				}
				return
			}
			if item.Sha256 == "" {
				// Malformed item — nothing to query without a sha256;
				// hand it to the upload path with Prehashed cleared so it
				// is hashed there.
				ctx.Counters.Inc("errors", 1)
				ctx.Log.Warn("precheck got item without sha256 (%s) — "+
					"routed to upload path", item.RelPath)
				item.Prehashed = false
				pending = append(pending, item)
				continue
			}
			batch = append(batch, item)
			if len(batch) == 1 {
				// Window starts at the first item — a slow-but-steady
				// feed can't push the flush out forever.
				timer.Reset(precheckFlushInterval)
			}
			if len(batch) >= batchSize {
				flush()
			}
		case workOut <- next:
			pending = pending[1:]
		case <-timer.C:
			flush()
			timer.Reset(precheckFlushInterval)
		}
	}
}
