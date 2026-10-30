// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// fie.go — File Inspection Engine client + ScanBackend adapter. Mirrors the
// FieClient/FieBackend pair in filescanner.py: synchronous verdicts via
// /check-sample (sha1) and POST /scan, shared availability cache, exp backoff.
// FIE is an unauthenticated internal service — no Authorization header.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Per-file permanence: 400 (size limit / malformed request) and 413 are never
// retriable. Everything else retries bounded by MaxUploadAttempts — 524 is
// FIE's own analysis timeout and must NOT be treated as permanent.
var fiePermanentStatuses = map[int]bool{400: true, 413: true}

const (
	fieHashTimeout = 30 * time.Second
	// FIE holds /scan for the whole analysis window and answers 524 on its
	// own timeout: read timeout N of Python timeout=(30, 600) — an
	// inactivity window (also the response-header wait), not a total cap.
	fieScanTimeout = 600 * time.Second
)

type FieClient struct {
	Host string
	hc   *http.Client
	// uploadIdle is the /scan read timeout N of Python timeout=(30, N).
	uploadIdle time.Duration

	availMu sync.Mutex
	availOK bool
	availAt time.Time
}

func NewFieClient(host string, verifySSL bool, proxy string) *FieClient {
	host = strings.TrimRight(host, "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL}, //nolint:gosec
		// Explicit config only: HTTP(S)_PROXY env vars must not override the
		// configured proxy setting (mirrors requests trust_env=False).
		Proxy: nil,
	}
	applyUploadTimeouts(tr, fieScanTimeout)
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &FieClient{Host: host, hc: &http.Client{Transport: tr},
		availOK: true, uploadIdle: fieScanTimeout}
}

// Probe GETs /readyz — 200 means the service can accept work.
func (c *FieClient) probe(timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.Host+"/readyz", nil)
	if err != nil {
		return false
	}
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect // never follow: body could re-POST cross-origin
	resp, err := cl.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// WaitReady polls probe until maxWait; a recovery propagates to the shared
// availability cache so gated workers resume immediately.
func (c *FieClient) WaitReady(maxWait, interval time.Duration,
	log *Logger) bool {
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if c.probe(8 * time.Second) {
			c.availMu.Lock()
			c.availOK = true
			c.availAt = time.Now()
			c.availMu.Unlock()
			return true
		}
		if log != nil {
			log.Warn("FIE not ready (%s/readyz); rechecking in %s",
				c.Host, interval)
		}
		time.Sleep(interval)
	}
	return false
}

// AvailableNow: shared cached probe — at most one /readyz GET per ttl across
// all workers. Fresh-False gates every worker without probing.
func (c *FieClient) AvailableNow(ttl time.Duration) bool {
	c.availMu.Lock()
	if time.Since(c.availAt) < ttl {
		ok := c.availOK
		c.availMu.Unlock()
		return ok
	}
	c.availMu.Unlock()
	ok := c.probe(8 * time.Second)
	c.availMu.Lock()
	c.availAt = time.Now()
	c.availOK = ok
	c.availMu.Unlock()
	return ok
}

// MarkUnavailable stamps a FRESH False so every worker gates for
// avail_probe_seconds without probing.
func (c *FieClient) MarkUnavailable() {
	c.availMu.Lock()
	c.availAt = time.Now()
	c.availOK = false
	c.availMu.Unlock()
}

type fieResult struct {
	status int
	body   map[string]any
	err    string
}

// CheckHash GETs /check-sample/hash/sha1/{sha1}; only a 200 yields a body.
func (c *FieClient) CheckHash(sha1 string) fieResult {
	ctx, cancel := context.WithTimeout(context.Background(), fieHashTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET",
		c.Host+"/check-sample/hash/sha1/"+sha1, nil)
	if err != nil {
		return fieResult{err: "request_error: " + err.Error()}
	}
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return fieResult{err: "request_error: " + err.Error()}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return fieResult{status: resp.StatusCode,
			err: fmt.Sprintf("http_%d: %.200s", resp.StatusCode, b)}
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		return fieResult{status: resp.StatusCode,
			err: "invalid check-sample response body"}
	}
	return fieResult{status: resp.StatusCode, body: body}
}

// ScanFile POSTs the raw file bytes to /scan with an explicit Content-Length
// (never chunked). externalID rides as the ?external_id= query param; empty
// means the param is omitted (fie_external_id=none).
func (c *FieClient) ScanFile(filePath, externalID string) fieResult {
	fi, err := os.Stat(filePath)
	if err != nil {
		return fieResult{err: "file_not_found: " + err.Error()}
	}
	u := c.Host + "/scan"
	if externalID != "" {
		u += "?external_id=" + url.QueryEscape(externalID)
	}
	f, err := openRegular(filePath)
	if err != nil {
		return fieResult{err: "file_not_found: " + err.Error()}
	}
	defer f.Close()
	ctx, guard, release := newIdleGuard(c.uploadIdle)
	defer release()
	req, err := http.NewRequestWithContext(ctx, "POST", u, guard.body(f))
	if err != nil {
		return fieResult{err: "request_error: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = fi.Size()
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return fieResult{err: "request_error: " + guard.err(ctx, err).Error()}
	}
	defer resp.Body.Close()
	b := guard.readResponse(resp.Body, 4<<20)
	if resp.StatusCode != 200 {
		return fieResult{status: resp.StatusCode,
			err: fmt.Sprintf("http_%d: %.200s", resp.StatusCode, b)}
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		return fieResult{status: resp.StatusCode,
			err: "invalid scan response body"}
	}
	return fieResult{status: resp.StatusCode, body: body}
}

// ---------------------------------------------------------------------------
// FieBackend — ScanBackend over FieClient. FIE answers the verdict
// synchronously on submit: IsSync()=true and PollBatch is never called.
// NeedsSHA1: /check-sample addresses samples by sha1.
//
// meta contract: may carry "rel_path" — the scan-root-relative path the
// pipeline stamps per file; used for externalID mode "rel_path".
// ---------------------------------------------------------------------------

type FieBackend struct {
	client     *FieClient
	mode       string
	trustOK    bool
	externalID string
}

func NewFieBackend(c *FieClient, mode string, trustOK bool,
	externalID string) *FieBackend {
	return &FieBackend{client: c, mode: mode, trustOK: trustOK,
		externalID: externalID}
}

func (b *FieBackend) Name() string     { return "fie" }
func (b *FieBackend) NeedsSHA1() bool  { return true }
func (b *FieBackend) IsSync() bool     { return true }
func (b *FieBackend) MarkUnavailable() { b.client.MarkUnavailable() }

func (b *FieBackend) Probe(timeout time.Duration) bool {
	return b.client.probe(timeout)
}

func (b *FieBackend) WaitReady(maxWait, interval time.Duration,
	log *Logger) bool {
	return b.client.WaitReady(maxWait, interval, log)
}

func (b *FieBackend) AvailableNow(ttl time.Duration) bool {
	return b.client.AvailableNow(ttl)
}

// fieVerdict normalizes a /scan or /check-sample response into a verdict:
// malicious/suspicious pass through, "OK" -> goodware, anything else ->
// unknown. threat fields come from threat_details; ReportJSON is the raw
// response re-marshaled.
func fieVerdict(body map[string]any, status int) SubmitOutcome {
	raw, _ := body["classification"].(string)
	cls := "unknown"
	switch raw {
	case "malicious", "suspicious":
		cls = raw
	case "OK":
		cls = "goodware"
	}
	o := SubmitOutcome{Kind: "verdict", HTTPStatus: intOrNil(status),
		Classification: &cls}
	if td, ok := body["threat_details"].(map[string]any); ok {
		if tn, ok := td["threat_name"].(string); ok && tn != "" {
			o.ThreatName = &tn
		}
		switch v := td["scanner_match"].(type) {
		case float64:
			f := int64(v)
			o.ThreatFactor = &f
		case int64:
			o.ThreatFactor = &v
		}
	}
	if j, err := json.Marshal(body); err == nil {
		s := string(j)
		o.ReportJSON = &s
	}
	return o
}

// externalIDValue resolves the configured external_id mode: rel_path ->
// meta["rel_path"]; filename -> basename; none -> "" (param omitted).
func (b *FieBackend) externalIDValue(filePath string,
	meta map[string]any) string {
	switch b.externalID {
	case "none":
		return ""
	case "filename":
		return filepath.Base(filePath)
	default: // rel_path
		if rel, ok := meta["rel_path"].(string); ok && rel != "" {
			return rel
		}
		return filepath.Base(filePath)
	}
}

func (b *FieBackend) scanSubmit(filePath string,
	meta map[string]any) SubmitOutcome {
	res := b.client.ScanFile(filePath, b.externalIDValue(filePath, meta))
	if res.body == nil {
		return SubmitOutcome{Kind: "error", HTTPStatus: intOrNil(res.status),
			Error: strOrNil(res.err)}
	}
	return fieVerdict(res.body, res.status)
}

// SubmitOnce runs one attempt per [fie] mode:
//
//	scan           — POST /scan straight to a verdict.
//	hash_then_scan — /check-sample first; malicious/suspicious is a verdict,
//	                 "OK" under trust_ok is a clean verdict, otherwise fall
//	                 through to /scan (also for unrecognized classifications).
//	hash_only      — /check-sample only; "OK" + !trust_ok records "unknown"
//	                 (FIE can't tell unseen from clean), ReportJSON keeps the
//	                 raw response.
func (b *FieBackend) SubmitOnce(filePath, sha256, sha1 string,
	meta map[string]any) SubmitOutcome {
	if b.mode == "scan" {
		return b.scanSubmit(filePath, meta)
	}
	res := b.client.CheckHash(sha1)
	if res.body == nil {
		return SubmitOutcome{Kind: "error", HTTPStatus: intOrNil(res.status),
			Error: strOrNil(res.err)}
	}
	raw, _ := res.body["classification"].(string)
	if raw == "malicious" || raw == "suspicious" {
		return fieVerdict(res.body, res.status)
	}
	if b.mode == "hash_only" {
		o := fieVerdict(res.body, res.status)
		if raw == "OK" && !b.trustOK {
			unknown := "unknown" // ambiguous: unseen vs clean
			o.Classification = &unknown
		}
		return o
	}
	if raw == "OK" && b.trustOK {
		return fieVerdict(res.body, res.status)
	}
	return b.scanSubmit(filePath, meta)
}

// SubmitWithBackoff mirrors DetectBackend's retry shape: every attempt gates
// on the shared availability cache; retriable failures (conn errors,
// timeouts, 408/429/5xx/524 — anything not in fiePermanentStatuses) back off
// exponentially inside UploadRetryWindow, bounded by MaxUploadAttempts.
// 400/413 return immediately.
func (b *FieBackend) SubmitWithBackoff(filePath, sha256, sha1 string,
	meta map[string]any, a *Args, log *Logger) SubmitOutcome {
	deadline := time.Now().Add(time.Duration(a.UploadRetryWindow) * time.Second)
	delay := time.Duration(max(1, a.BackoffBase)) * time.Second
	attempts := 0
	var last SubmitOutcome
	for attempts < a.MaxUploadAttempts {
		if !b.client.AvailableNow(
			time.Duration(a.AvailProbeSeconds) * time.Second) {
			if log != nil {
				log.Warn("FIE not available — pausing scan of %s",
					filepath.Base(filePath))
			}
			b.client.WaitReady(time.Duration(a.ReadyMaxWait)*time.Second,
				time.Duration(a.ReadyCheckInterval)*time.Second, log)
		}
		attempts++
		last = b.SubmitOnce(filePath, sha256, sha1, meta)
		if last.Kind != "error" {
			return last
		}
		if last.HTTPStatus != nil && fiePermanentStatuses[*last.HTTPStatus] {
			return last
		}
		// conn error / saturation / server-side failure — gate all workers on
		// the shared cache instead of racing a sick service.
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
			log.Warn("FIE submit attempt %d failed (%s); retry in %.0fs",
				attempts, errStr, wait.Seconds())
		}
		time.Sleep(wait)
		delay *= 2
		if mx := time.Duration(a.BackoffMax) * time.Second; delay > mx {
			delay = mx
		}
	}
	return last
}

// PollBatch is unused — FIE is synchronous (IsSync) so verdicts land in
// SubmitOnce and rows go pending -> done directly. Defined for ScanBackend.
func (b *FieBackend) PollBatch(refs []PollRef) map[string]any {
	return map[string]any{}
}
