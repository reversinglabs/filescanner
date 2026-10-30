// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// cloud.go — CloudBackend: ScanBackend over TicloudClient. Async: SubmitOnce
// runs the spex two-step upload (binary POST /api/spex/upload/{sha1}, then
// the metadata XML the pipeline requires before the sample is processed)
// and returns the sha1 as the receipt; PollBatch resolves TCA-0101
// reputation by sha1 — status != UNKNOWN -> normalized verdict map,
// UNKNOWN -> "pending". NeedsSHA1=true: spex addresses samples by sha1.
//
// meta contract: unused — no per-file submit metadata today (domain and
// archive_password come from [ticloud] config).
package main

import (
	"path/filepath"
	"strings"
	"time"
)

type CloudBackend struct {
	client          *TicloudClient
	domain          string
	archivePassword string
}

func NewCloudBackend(c *TicloudClient, domain,
	archivePassword string) *CloudBackend {
	return &CloudBackend{client: c, domain: domain,
		archivePassword: archivePassword}
}

func (b *CloudBackend) Name() string     { return "cloud" }
func (b *CloudBackend) NeedsSHA1() bool  { return true }
func (b *CloudBackend) IsSync() bool     { return false }
func (b *CloudBackend) MarkUnavailable() { b.client.MarkUnavailable() }

func (b *CloudBackend) Probe(timeout time.Duration) bool {
	return b.client.probe(timeout)
}

func (b *CloudBackend) WaitReady(maxWait, interval time.Duration,
	log *Logger) bool {
	return b.client.WaitReady(maxWait, interval, log)
}

func (b *CloudBackend) AvailableNow(ttl time.Duration) bool {
	return b.client.AvailableNow(ttl)
}

// submitOnce runs one spex submit (binary then meta, or meta only when
// sampleUploaded is set) -> receipt ref=sha1 | error outcome.
func (b *CloudBackend) submitOnce(filePath, sha1 string,
	sampleUploaded bool) SubmitOutcome {
	res := b.client.SubmitSample(sha1, filePath, "", b.domain,
		b.archivePassword, sampleUploaded)
	if res.err == "" {
		return SubmitOutcome{Kind: "receipt",
			Ref:        strings.ToLower(sha1),
			HTTPStatus: intOrNil(res.status)}
	}
	return SubmitOutcome{Kind: "error", HTTPStatus: intOrNil(res.status),
		Error: strOrNil(res.err)}
}

func (b *CloudBackend) SubmitOnce(filePath, sha256, sha1 string,
	meta map[string]any) SubmitOutcome {
	return b.submitOnce(filePath, sha1, false)
}

// SubmitWithBackoff mirrors A1000Backend's retry shape: every attempt gates
// on the shared availability cache; retriable failures (conn errors,
// timeouts, 408/429/5xx) back off exponentially inside UploadRetryWindow
// bounded by MaxUploadAttempts. 413 returns immediately; 401/403 are never
// retried (the factory's startup probe already failed fast on bad
// credentials).
//
// spex-specific: a "meta_failed:" error means the binary is already stored
// under its sha1 — the next attempt posts ONLY the meta step
// (sampleUploaded=true), never re-uploading the file.
func (b *CloudBackend) SubmitWithBackoff(filePath, sha256, sha1 string,
	meta map[string]any, a *Args, log *Logger) SubmitOutcome {
	deadline := time.Now().Add(
		time.Duration(a.UploadRetryWindow) * time.Second)
	delay := time.Duration(max(1, a.BackoffBase)) * time.Second
	attempts := 0
	sampleUploaded := false
	var last SubmitOutcome
	for attempts < a.MaxUploadAttempts {
		if !b.client.AvailableNow(
			time.Duration(a.AvailProbeSeconds) * time.Second) {
			if log != nil {
				log.Warn("TiCloud not available — pausing upload of %s",
					filepath.Base(filePath))
			}
			b.client.WaitReady(time.Duration(a.ReadyMaxWait)*time.Second,
				time.Duration(a.ReadyCheckInterval)*time.Second, log)
		}
		attempts++
		last = b.submitOnce(filePath, sha1, sampleUploaded)
		if last.Kind != "error" {
			return last
		}
		if last.Error != nil &&
			strings.HasPrefix(*last.Error, "meta_failed:") {
			// binary already stored under sha1 — retry posts meta only
			sampleUploaded = true
		}
		if last.HTTPStatus != nil &&
			(ticloudPermanentStatuses[*last.HTTPStatus] ||
				ticloudAuthStatuses[*last.HTTPStatus]) {
			return last
		}
		// conn error / saturation / server-side failure — gate all workers
		// on the shared cache instead of racing a sick service.
		if last.HTTPStatus == nil || *last.HTTPStatus == 429 ||
			*last.HTTPStatus >= 500 {
			b.client.MarkUnavailable()
		}
		if time.Now().After(deadline) {
			break
		}
		if !b.client.WaitReady(time.Duration(a.ReadyMaxWait)*time.Second,
			time.Duration(a.ReadyCheckInterval)*time.Second,
			log) && log != nil {
			log.Warn("readyz gate timed out after %ds; retrying anyway",
				a.ReadyMaxWait)
		}
		wait := delay
		if rem := time.Until(deadline); rem < wait {
			wait = max(0, rem)
		}
		if log != nil {
			errStr := ""
			if last.Error != nil {
				errStr = *last.Error
			}
			log.Warn("TiCloud submit attempt %d failed (%s); "+
				"retry in %.0fs", attempts, errStr, wait.Seconds())
		}
		time.Sleep(wait)
		delay *= 2
		if mx := time.Duration(a.BackoffMax) * time.Second; delay > mx {
			delay = mx
		}
	}
	return last
}

// ticloudEntryHashes collects every hash an extended TCA-0101 entry echoes,
// lower-cased. Real responses nest them under query_hash/sample_hash
// ({"sha1": "..."}); flat sha1/md5/sha256/hash_value keys also occur (and
// are what test mocks use).
func ticloudEntryHashes(e map[string]any) []string {
	var out []string
	for _, k := range []string{"sha1", "md5", "sha256", "hash_value"} {
		if v, ok := e[k].(string); ok && v != "" {
			out = append(out, strings.ToLower(v))
		}
	}
	for _, k := range []string{"query_hash", "sample_hash"} {
		if sub, ok := e[k].(map[string]any); ok {
			for _, v := range sub {
				if s, ok := v.(string); ok && s != "" {
					out = append(out, strings.ToLower(s))
				}
			}
		}
	}
	return out
}

// PollBatch bulk-polls by sha1 (the receipt ref IS the sha1). TCA-0101
// status != UNKNOWN -> normalized verdict map {classification, threat_name,
// threat_factor, report_json=raw entry}; UNKNOWN / missing / bulk failure
// -> "pending" (rows time out via report_wait_hours, like evicted tiscale
// tasks).
func (b *CloudBackend) PollBatch(refs []PollRef) map[string]any {
	out := make(map[string]any, len(refs))
	type pair struct{ ref, hash string }
	var pairs []pair
	for _, pr := range refs {
		ref := pr.Ref
		if ref == "" {
			continue
		}
		h := strings.ToLower(ref)
		if !isA1000SHA1(h) {
			out[ref] = "pending" // cloud receipts are sha1 — nothing to poll with
			continue
		}
		pairs = append(pairs, pair{ref, h})
	}
	if len(pairs) == 0 {
		return out
	}
	hashes := make([]string, len(pairs))
	for i, p := range pairs {
		hashes[i] = p.hash
	}
	_, entries, _, _ := b.client.ReputationBulk(hashes, "sha1")
	if entries == nil { // bulk call failed / empty — all transient
		for _, p := range pairs {
			out[p.ref] = "pending"
		}
		return out
	}
	byHash := map[string]map[string]any{}
	for _, e := range entries {
		for _, h := range ticloudEntryHashes(e) {
			if _, dup := byHash[h]; !dup {
				byHash[h] = e
			}
		}
	}
	for _, p := range pairs {
		ent := byHash[p.hash]
		if ent == nil {
			out[p.ref] = "pending"
			continue
		}
		v := normalizeReputationEntry(ent)
		if v["classification"] == "unknown" {
			out[p.ref] = "pending"
			continue
		}
		out[p.ref] = map[string]any{
			"classification": v["classification"],
			"threat_name":    v["threat_name"],
			"threat_factor":  v["threat_factor"],
			"report_json":    v["raw"],
		}
	}
	return out
}
