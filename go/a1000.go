// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// a1000.go — Spectra Analyze (A1000) client + ScanBackend adapter. Mirrors the
// A1000Client/A1000Backend pair in filescanner.py: multipart POST
// /api/uploads/ -> detail.sha1 receipt, bulk /api/samples/status/ polling by
// sha256, verdicts from /api/samples/v3/{h}/classification/ (summary) or
// /api/samples/v2/list/details/ (full). Authenticated via `Authorization:
// Token` — no request ever follows a redirect (the token must not leak to a
// redirect target) and it is redacted from any error text.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Per-file permanence: 400 (malformed request) and 413 (file too large) are
// never retriable. Everything else retries bounded by MaxUploadAttempts;
// 429/5xx/conn/timeout also flip the shared availability gate.
var a1000PermanentStatuses = map[int]bool{400: true, 413: true}

const (
	a1000StatusChunk = 100 // /api/samples/status/ caps hash_values at 100
	// Upload read timeout N of Python timeout=(30, 300) — an inactivity
	// window, not a whole-request deadline; list/details can be slow (the
	// API documents highly variable response speeds) so they get 150s.
	a1000UploadTimeout = 300 * time.Second
	a1000PollTimeout   = 30 * time.Second
	a1000ReportTimeout = 150 * time.Second
)

var a1000DetailFields = []string{
	"sha256", "classification_result", "classification", "riskscore",
	"av_scanners_summary", "sample_summary", "tags"}

// isA1000Hash reports whether s is a hex hash the status/classification
// endpoints accept (MD5/SHA1/SHA256/SHA512).
func isA1000Hash(s string) bool {
	switch len(s) {
	case 32, 40, 64, 128:
	default:
		return false
	}
	for _, r := range s {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'f' ||
			'A' <= r && r <= 'F') {
			return false
		}
	}
	return true
}

func isA1000SHA1(s string) bool { return len(s) == 40 && isA1000Hash(s) }

// a1000Clean strips characters that could break a multipart part header.
func a1000Clean(v string) string {
	return strings.NewReplacer(`"`, "_", "\r", "", "\n", "").Replace(v)
}

type A1000Client struct {
	Host string
	hc   *http.Client
	// uploadIdle is the upload read timeout N of Python timeout=(30, N).
	uploadIdle time.Duration
	token      string

	availMu sync.Mutex
	availOK bool
	availAt time.Time
}

func NewA1000Client(host, token string, verifySSL bool, proxy string) *A1000Client {
	host = strings.TrimRight(host, "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL}, //nolint:gosec
		// Explicit config only: HTTP(S)_PROXY env vars must not override the
		// configured proxy setting (mirrors requests trust_env=False).
		Proxy: nil,
	}
	applyUploadTimeouts(tr, a1000UploadTimeout)
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &A1000Client{Host: host, token: token,
		hc: &http.Client{Transport: tr}, availOK: true,
		uploadIdle: a1000UploadTimeout}
}

func (c *A1000Client) newReq(ctx context.Context, method, rawURL string,
	body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+c.token)
	return req, nil
}

// errText renders a response body for an error string — the token is redacted
// even if the appliance echoes request headers back.
func (c *A1000Client) errText(b []byte) string {
	t := string(b)
	if len(t) > 200 {
		t = t[:200]
	}
	if c.token != "" {
		t = strings.ReplaceAll(t, c.token, "***")
	}
	return t
}

// probeStatus GETs {host}/api/uploads/ -> (status, answered). Any HTTP answer
// < 500 means the appliance is up — 401/403/405 still mean reachable
// (makeBackend reads the code for the auth check).
func (c *A1000Client) probeStatus(timeout time.Duration) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := c.newReq(ctx, "GET", c.Host+"/api/uploads/", nil)
	if err != nil {
		return 0, false
	}
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return 0, false
	}
	resp.Body.Close()
	return resp.StatusCode, true
}

func (c *A1000Client) probe(timeout time.Duration) bool {
	st, ok := c.probeStatus(timeout)
	return ok && st < 500
}

// WaitReady polls probe until maxWait; a recovery propagates to the shared
// availability cache so gated workers resume immediately.
func (c *A1000Client) WaitReady(maxWait, interval time.Duration,
	log *Logger) bool {
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if c.probe(8 * time.Second) {
			c.availMu.Lock() // propagate recovery to all workers
			c.availOK = true
			c.availAt = time.Now()
			c.availMu.Unlock()
			return true
		}
		if log != nil {
			log.Warn("A1000 not ready (%s/api/uploads/); rechecking in %s",
				c.Host, interval)
		}
		time.Sleep(interval)
	}
	return false
}

// AvailableNow: shared cached probe — at most one probe per ttl across all
// workers. Fresh-False gates every worker without probing.
func (c *A1000Client) AvailableNow(ttl time.Duration) bool {
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
func (c *A1000Client) MarkUnavailable() {
	c.availMu.Lock()
	c.availAt = time.Now()
	c.availOK = false
	c.availMu.Unlock()
}

type a1000UploadResult struct {
	status int
	sha1   string
	err    string
}

// Upload POSTs /api/uploads/ as a streamed multipart body with an explicit
// Content-Length: one form field per configured option (filename is always
// the basename) plus the file part. 201 -> detail.sha1 (validated 40-hex).
func (c *A1000Client) Upload(filePath string,
	fields map[string]string) a1000UploadResult {
	fi, err := os.Stat(filePath)
	if err != nil {
		return a1000UploadResult{err: "file_not_found: " + err.Error()}
	}
	fileSize := fi.Size()
	fname := a1000Clean(filepath.Base(filePath))
	boundary := "----rlscan" + strings.ReplaceAll(uuid.NewString(), "-", "")

	var head strings.Builder
	fmt.Fprintf(&head, "--%s\r\n"+
		"Content-Disposition: form-data; name=\"filename\"\r\n"+
		"\r\n%s\r\n", boundary, fname)
	keys := make([]string, 0, len(fields))
	for k, v := range fields {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys) // deterministic part order on the wire
	for _, k := range keys {
		fmt.Fprintf(&head, "--%s\r\n"+
			"Content-Disposition: form-data; name=\"%s\"\r\n"+
			"\r\n%s\r\n", boundary, a1000Clean(k), a1000Clean(fields[k]))
	}
	fmt.Fprintf(&head, "--%s\r\n"+
		"Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"+
		"Content-Type: application/octet-stream\r\n\r\n", boundary, fname)
	tail := fmt.Sprintf("\r\n--%s--\r\n", boundary)
	headB := []byte(head.String())
	totalLen := int64(len(headB)) + fileSize + int64(len(tail))

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if _, err := pw.Write(headB); err != nil {
			return
		}
		f, err := openRegular(filePath)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.CopyBuffer(pw, f, make([]byte, IOChunkSize)); err != nil {
			f.Close()
			pw.CloseWithError(err)
			return
		}
		f.Close()
		pw.Write([]byte(tail))
	}()

	ctx, guard, release := newIdleGuard(c.uploadIdle)
	defer release()
	req, err := c.newReq(ctx, "POST", c.Host+"/api/uploads/", guard.body(pr))
	if err != nil {
		return a1000UploadResult{err: "request_error: " + err.Error()}
	}
	req.Header.Set("Content-Type",
		fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
	req.ContentLength = totalLen
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect // never follow: token/body would leak
	resp, err := cl.Do(req)
	if err != nil {
		return a1000UploadResult{
			err: "request_error: " + guard.err(ctx, err).Error()}
	}
	defer resp.Body.Close()
	body := guard.readResponse(resp.Body, 4<<20)
	code := resp.StatusCode
	if code != 201 {
		return a1000UploadResult{status: code,
			err: fmt.Sprintf("http_%d: %s", code, c.errText(body))}
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return a1000UploadResult{status: code,
			err: "invalid upload response body"}
	}
	var sha1 string
	if detail, ok := parsed["detail"].(map[string]any); ok {
		sha1, _ = detail["sha1"].(string)
	}
	if !isA1000SHA1(sha1) {
		return a1000UploadResult{status: code, err: "no sha1 in response"}
	}
	return a1000UploadResult{status: code, sha1: sha1}
}

type a1000Result struct {
	status int
	body   map[string]any
	err    string
}

// StatusBulk POSTs /api/samples/status/ chunked at a1000StatusChunk (API max
// 100) -> (status, {hash_value: status}, err). One failing chunk fails the
// whole call. Map keys are lower-cased for lookup.
func (c *A1000Client) StatusBulk(hashes []string) (int, map[string]string,
	string) {
	merged := map[string]string{}
	lastStatus := 0
	for i := 0; i < len(hashes); i += a1000StatusChunk {
		end := i + a1000StatusChunk
		if end > len(hashes) {
			end = len(hashes)
		}
		payload, _ := json.Marshal(
			map[string]any{"hash_values": hashes[i:end]})
		ctx, cancel := context.WithTimeout(context.Background(),
			a1000PollTimeout)
		req, err := c.newReq(ctx, "POST", c.Host+"/api/samples/status/",
			bytes.NewReader(payload))
		if err != nil {
			cancel()
			return 0, nil, "request_error: " + err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		cl := *c.hc
		cl.CheckRedirect = checkNoRedirect
		resp, err := cl.Do(req)
		if err != nil {
			cancel()
			return 0, nil, "request_error: " + err.Error()
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		cancel()
		lastStatus = resp.StatusCode
		if resp.StatusCode != 200 {
			return resp.StatusCode, nil, fmt.Sprintf("http_%d: %s",
				resp.StatusCode, c.errText(b))
		}
		var parsed map[string]any
		if err := json.Unmarshal(b, &parsed); err != nil {
			return resp.StatusCode, nil, "invalid status response body"
		}
		results, ok := parsed["results"].([]any)
		if !ok {
			return resp.StatusCode, nil, "invalid status response body"
		}
		for _, e := range results {
			ent, ok := e.(map[string]any)
			if !ok {
				continue
			}
			hv, _ := ent["hash_value"].(string)
			st, _ := ent["status"].(string)
			if hv != "" && st != "" {
				merged[strings.ToLower(hv)] = st
			}
		}
	}
	return lastStatus, merged, ""
}

// Classification GETs /api/samples/v3/{h}/classification/ -> the
// classification doc on 200.
func (c *A1000Client) Classification(hash string) a1000Result {
	ctx, cancel := context.WithTimeout(context.Background(), a1000PollTimeout)
	defer cancel()
	req, err := c.newReq(ctx, "GET",
		c.Host+"/api/samples/v3/"+hash+"/classification/", nil)
	if err != nil {
		return a1000Result{err: "request_error: " + err.Error()}
	}
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return a1000Result{err: "request_error: " + err.Error()}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return a1000Result{status: resp.StatusCode,
			err: fmt.Sprintf("http_%d: %s", resp.StatusCode, c.errText(b))}
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		return a1000Result{status: resp.StatusCode,
			err: "invalid classification response body"}
	}
	return a1000Result{status: resp.StatusCode, body: body}
}

// FullReport POSTs /api/samples/v2/list/details/ {hash_values, fields} -> the
// response body (a `results` list with one entry per hash) on 200.
func (c *A1000Client) FullReport(hashes []string) a1000Result {
	payload, _ := json.Marshal(map[string]any{
		"hash_values": hashes,
		"fields":      a1000DetailFields,
	})
	ctx, cancel := context.WithTimeout(context.Background(), a1000ReportTimeout)
	defer cancel()
	req, err := c.newReq(ctx, "POST",
		c.Host+"/api/samples/v2/list/details/", bytes.NewReader(payload))
	if err != nil {
		return a1000Result{err: "request_error: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return a1000Result{err: "request_error: " + err.Error()}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return a1000Result{status: resp.StatusCode,
			err: fmt.Sprintf("http_%d: %s", resp.StatusCode, c.errText(b))}
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		return a1000Result{status: resp.StatusCode,
			err: "invalid report response body"}
	}
	return a1000Result{status: resp.StatusCode, body: body}
}

// ---------------------------------------------------------------------------
// A1000Backend — ScanBackend over A1000Client. Async: SubmitOnce returns a
// receipt (the sha1 A1000 assigns at upload), PollBatch resolves statuses by
// sha256. NeedsSHA1=false: the status/classification APIs accept sha256, so
// the hash pass stays sha256-only.
//
// meta contract: unused — no per-file submit metadata today.
// ---------------------------------------------------------------------------

type A1000Backend struct {
	client       *A1000Client
	fields       map[string]string // optional /api/uploads/ form fields
	reportDetail string            // "summary" | "full"
}

func NewA1000Backend(c *A1000Client, fields map[string]string,
	reportDetail string) *A1000Backend {
	return &A1000Backend{client: c, fields: fields, reportDetail: reportDetail}
}

func (b *A1000Backend) Name() string     { return "a1000" }
func (b *A1000Backend) NeedsSHA1() bool  { return false }
func (b *A1000Backend) IsSync() bool     { return false }
func (b *A1000Backend) MarkUnavailable() { b.client.MarkUnavailable() }

func (b *A1000Backend) Probe(timeout time.Duration) bool {
	return b.client.probe(timeout)
}

func (b *A1000Backend) WaitReady(maxWait, interval time.Duration,
	log *Logger) bool {
	return b.client.WaitReady(maxWait, interval, log)
}

func (b *A1000Backend) AvailableNow(ttl time.Duration) bool {
	return b.client.AvailableNow(ttl)
}

func (b *A1000Backend) SubmitOnce(filePath, sha256, sha1 string,
	meta map[string]any) SubmitOutcome {
	res := b.client.Upload(filePath, b.fields)
	if res.sha1 != "" {
		return SubmitOutcome{Kind: "receipt", Ref: res.sha1,
			HTTPStatus: intOrNil(res.status)}
	}
	return SubmitOutcome{Kind: "error", HTTPStatus: intOrNil(res.status),
		Error: strOrNil(res.err)}
}

// SubmitWithBackoff mirrors FieBackend's retry shape: every attempt gates on
// the shared availability cache; retriable failures (conn errors, timeouts,
// 408/429/5xx — anything not in a1000PermanentStatuses) back off
// exponentially inside UploadRetryWindow, bounded by MaxUploadAttempts.
// 400/413 return immediately.
func (b *A1000Backend) SubmitWithBackoff(filePath, sha256, sha1 string,
	meta map[string]any, a *Args, log *Logger) SubmitOutcome {
	deadline := time.Now().Add(time.Duration(a.UploadRetryWindow) * time.Second)
	delay := time.Duration(max(1, a.BackoffBase)) * time.Second
	attempts := 0
	var last SubmitOutcome
	for attempts < a.MaxUploadAttempts {
		if !b.client.AvailableNow(
			time.Duration(a.AvailProbeSeconds) * time.Second) {
			if log != nil {
				log.Warn("A1000 not available — pausing upload of %s",
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
		if last.HTTPStatus != nil && a1000PermanentStatuses[*last.HTTPStatus] {
			return last
		}
		// conn error / saturation / server-side failure — gate all workers on
		// the shared cache instead of racing a sick appliance.
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
			log.Warn("A1000 submit attempt %d failed (%s); retry in %.0fs",
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

// a1000VerdictMap normalizes a classification doc / list/details entry into a
// poll verdict map (same shape as DetectBackend.PollBatch entries):
// MALICIOUS->malicious, SUSPICIOUS->suspicious, GOODWARE->goodware,
// UNKNOWN->unknown; threat_name=classification_result; factor=riskscore
// (0-10); report_json=the raw doc.
func a1000VerdictMap(body map[string]any) map[string]any {
	raw, _ := body["classification"].(string)
	cls := "unknown"
	switch strings.ToUpper(raw) {
	case "MALICIOUS":
		cls = "malicious"
	case "SUSPICIOUS":
		cls = "suspicious"
	case "GOODWARE":
		cls = "goodware"
	case "UNKNOWN":
		cls = "unknown"
	}
	var threatAny any
	if tn, ok := body["classification_result"].(string); ok && tn != "" {
		threatAny = tn
	}
	var factor *int64
	switch v := body["riskscore"].(type) {
	case float64:
		f := int64(v)
		factor = &f
	case int64: // test-injected maps may carry ints directly
		factor = &v
	}
	return map[string]any{
		"classification": cls,
		"threat_name":    threatAny,
		"threat_factor":  factor,
		"report_json":    body,
	}
}

// a1000DetailEntry picks the entry for hash out of a list/details response —
// sha256 match first, then any dict entry (single-hash requests).
func a1000DetailEntry(body map[string]any, hash string) map[string]any {
	results, _ := body["results"].([]any)
	var first map[string]any
	for _, e := range results {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if first == nil {
			first = m
		}
		if hv, _ := m["sha256"].(string); hv != "" &&
			strings.EqualFold(hv, hash) {
			return m
		}
	}
	return first
}

// pollVerdict fetches the verdict doc per report_detail for a 'processed'
// sample. Returns nil on any transient fetch failure (caller maps it to
// "pending" and retries next sweep).
func (b *A1000Backend) pollVerdict(hash string) map[string]any {
	if b.reportDetail == "full" {
		res := b.client.FullReport([]string{hash})
		if res.body == nil {
			return nil
		}
		entry := a1000DetailEntry(res.body, hash)
		if entry == nil {
			return nil
		}
		return a1000VerdictMap(entry)
	}
	res := b.client.Classification(hash)
	if res.body == nil {
		return nil
	}
	return a1000VerdictMap(res.body)
}

// PollBatch bulk-polls by sha256 (refs carry the row's sha256; the receipt
// ref — a sha1 — is itself a valid hash fallback). "processed" -> fetch and
// normalize the verdict; "not_found", missing, or any transient fetch error
// -> "pending" (rows time out via report_wait_hours, like evicted tiscale
// tasks).
func (b *A1000Backend) PollBatch(refs []PollRef) map[string]any {
	out := make(map[string]any, len(refs))
	type pair struct{ ref, hash string }
	var pairs []pair
	for _, pr := range refs {
		ref := pr.Ref
		if ref == "" {
			continue
		}
		h := pr.Sha256
		if !isA1000Hash(h) {
			if isA1000Hash(ref) {
				h = ref
			} else {
				h = ""
			}
		}
		if h == "" {
			out[ref] = "pending" // nothing to poll with — keep waiting
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
	_, statuses, _ := b.client.StatusBulk(hashes)
	if statuses == nil { // bulk call failed — all transient
		for _, p := range pairs {
			out[p.ref] = "pending"
		}
		return out
	}
	for _, p := range pairs {
		if !strings.EqualFold(statuses[strings.ToLower(p.hash)],
			"processed") {
			out[p.ref] = "pending" // not_found / missing / still working
			continue
		}
		if v := b.pollVerdict(p.hash); v != nil {
			out[p.ref] = v
		} else {
			out[p.ref] = "pending"
		}
	}
	return out
}
