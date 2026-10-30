// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// ticloud.go — Spectra Intelligence (TitaniumCloud) client. Mirrors
// TiCloudClient in filescanner.py: HTTP Basic auth, spex two-step upload
// (POST /api/spex/upload/{sha1} octet-stream, then POST .../meta XML — the
// metadata is required before the sample is processed), TCA-0101 reputation
// queries (bulk + single), and client-side min-interval pacing on spex
// POSTs (the API allows 10 req/s). No request ever follows a redirect —
// Basic credentials and the sample body must never leak to a redirect
// target — and credentials are redacted from every error string.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
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

// Error taxonomy: 401/403 are auth failures (the factory fail-fast reads
// probeStatus), 413 is permanent per file, 408/429/5xx/conn/timeout are
// retriable.
var ticloudAuthStatuses = map[int]bool{401: true, 403: true}
var ticloudPermanentStatuses = map[int]bool{413: true}
var ticloudRetriableStatuses = map[int]bool{408: true, 429: true} // +5xx/conn/timeout

const (
	ticloudReputationChunk = 100 // bulk_query caps hashes at 100
	ticloudQueryTimeout    = 30 * time.Second
)

var ticloudHashTypes = map[string]bool{"md5": true, "sha1": true,
	"sha256": true}

// normalizeReputationEntry maps a TCA-0101 extended entry to the shared
// verdict shape used by the cloud poll and the reputation pre-check:
// MALICIOUS->malicious, SUSPICIOUS->suspicious, KNOWN->goodware,
// UNKNOWN->unknown (unrecognized -> unknown); threat_factor is threat_level
// for malicious/suspicious, trust_factor for KNOWN; "raw" keeps the full
// entry (extended fields incl. scanner_*).
func normalizeReputationEntry(entry map[string]any) map[string]any {
	if entry == nil {
		entry = map[string]any{}
	}
	raw, _ := entry["status"].(string)
	cls := "unknown"
	switch strings.ToUpper(raw) {
	case "MALICIOUS":
		cls = "malicious"
	case "SUSPICIOUS":
		cls = "suspicious"
	case "KNOWN":
		cls = "goodware"
	case "UNKNOWN":
		cls = "unknown"
	}
	var threatName any
	if tn, ok := entry["threat_name"].(string); ok && tn != "" {
		threatName = tn
	}
	var fv any
	switch cls {
	case "malicious", "suspicious":
		fv = entry["threat_level"]
	case "goodware":
		fv = entry["trust_factor"]
	}
	var factor *int64
	switch v := fv.(type) {
	case float64:
		f := int64(v)
		factor = &f
	case int64: // test-injected maps may carry ints directly
		factor = &v
	}
	return map[string]any{
		"classification": cls,
		"threat_name":    threatName,
		"threat_factor":  factor,
		"raw":            entry,
	}
}

// ticloudXMLEscape escapes a value for XML element content.
func ticloudXMLEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// ticloudMetaXML renders the upload metadata document the spex pipeline
// requires — <domain> is always present (empty when unconfigured); the
// <archive> element appears only when archivePassword is set. Every
// interpolated value is XML-escaped.
func ticloudMetaXML(filename, domain, archivePassword string) string {
	var b strings.Builder
	b.WriteString("<rl><properties><property><name>filename</name><value>")
	b.WriteString(ticloudXMLEscape(filepath.Base(filename)))
	b.WriteString("</value></property><property><name>source</name>" +
		"<value>filescanner</value></property></properties><domain>")
	b.WriteString(ticloudXMLEscape(domain))
	b.WriteString("</domain>")
	if archivePassword != "" {
		b.WriteString("<archive><archive_passwords><password>")
		b.WriteString(ticloudXMLEscape(archivePassword))
		b.WriteString("</password></archive_passwords></archive>")
	}
	b.WriteString("</rl>")
	return b.String()
}

// ticloudList coerces a response field to []any (nil-safe).
func ticloudList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

type TicloudClient struct {
	Host          string
	hc            *http.Client
	upHC          *http.Client // spex uploads (upload_timeout bounds)
	user          string
	pass          string
	uploadTimeout time.Duration
	minInterval   time.Duration
	extended      bool

	spexMu   sync.Mutex
	spexLast time.Time

	availMu sync.Mutex
	availOK bool
	availAt time.Time
}

func NewTicloudClient(host, username, password string, verifySSL bool,
	proxy string, uploadTimeout, minInterval time.Duration,
	extended bool) *TicloudClient {
	host = strings.TrimRight(host, "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL}, //nolint:gosec
		// Explicit config only: HTTP(S)_PROXY env vars must not override the
		// configured proxy setting (mirrors requests trust_env=False).
		Proxy: nil,
	}
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	if uploadTimeout <= 0 {
		uploadTimeout = 300 * time.Second
	}
	// Spex uploads: Python timeout=(30, upload_timeout) — inactivity window
	// + response-header wait, never a whole-request deadline. A separate
	// transport so a small upload_timeout never cuts query/precheck calls.
	upTr := tr.Clone()
	applyUploadTimeouts(upTr, uploadTimeout)
	return &TicloudClient{Host: host, user: username, pass: password,
		uploadTimeout: uploadTimeout, minInterval: minInterval,
		extended: extended, hc: &http.Client{Transport: tr},
		upHC: &http.Client{Transport: upTr}, availOK: true}
}

func (c *TicloudClient) newReq(ctx context.Context, method, rawURL string,
	body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.pass) // Authorization: Basic base64(user:pass)
	return req, nil
}

// redact strips credentials from any string destined for an error/log —
// password first, then username.
func (c *TicloudClient) redact(t string) string {
	if c.pass != "" {
		t = strings.ReplaceAll(t, c.pass, "***")
	}
	if c.user != "" {
		t = strings.ReplaceAll(t, c.user, "***")
	}
	return t
}

// errText renders a response body for an error string — Basic credentials
// can never appear in it even if the server echoes request headers back.
func (c *TicloudClient) errText(b []byte) string {
	t := string(b)
	if len(t) > 200 {
		t = t[:200]
	}
	return c.redact(t)
}

func (c *TicloudClient) reqErr(e error) string {
	return "request_error: " + c.redact(e.Error())
}

// paceSpex enforces min_interval pacing on spex POSTs via one shared
// timestamp across all goroutines.
func (c *TicloudClient) paceSpex() {
	if c.minInterval <= 0 {
		return
	}
	c.spexMu.Lock()
	defer c.spexMu.Unlock()
	if wait := c.minInterval - time.Since(c.spexLast); wait > 0 {
		time.Sleep(wait)
	}
	c.spexLast = time.Now()
}

// probeStatus GETs {host}/ -> (status, answered). Any HTTP answer < 500
// means the service is up — 401/403 still mean reachable (the factory reads
// the code for the auth fail-fast check).
func (c *TicloudClient) probeStatus(timeout time.Duration) (int, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := c.newReq(ctx, "GET", c.Host+"/", nil)
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

func (c *TicloudClient) probe(timeout time.Duration) bool {
	st, ok := c.probeStatus(timeout)
	return ok && st < 500
}

// WaitReady polls probe until maxWait; a recovery propagates to the shared
// availability cache so gated workers resume immediately.
func (c *TicloudClient) WaitReady(maxWait, interval time.Duration,
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
			log.Warn("TiCloud not ready (%s/); rechecking in %s",
				c.Host, interval)
		}
		time.Sleep(interval)
	}
	return false
}

// AvailableNow: shared cached probe — at most one probe per ttl across all
// workers. Fresh-False gates every worker without probing.
func (c *TicloudClient) AvailableNow(ttl time.Duration) bool {
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
func (c *TicloudClient) MarkUnavailable() {
	c.availMu.Lock()
	c.availAt = time.Now()
	c.availOK = false
	c.availMu.Unlock()
}

type ticloudResult struct {
	status int
	ok     bool
	err    string
}

// UploadSample POSTs the raw file bytes to /api/spex/upload/{sha1} with an
// explicit Content-Length (streamed from disk, never buffered in RAM). sha1
// is a lowercase 40-hex path param. Any 2xx means the sample is stored.
func (c *TicloudClient) UploadSample(sha1, filePath string) ticloudResult {
	sha1 = strings.ToLower(sha1)
	if !isA1000SHA1(sha1) { // same 40-hex validator as A1000
		return ticloudResult{err: "invalid sha1"}
	}
	fi, err := os.Stat(filePath)
	if err != nil {
		return ticloudResult{err: "file_not_found: " + err.Error()}
	}
	f, err := openRegular(filePath)
	if err != nil {
		return ticloudResult{err: "file_not_found: " + err.Error()}
	}
	defer f.Close()
	ctx, guard, release := newIdleGuard(c.uploadTimeout)
	defer release()
	req, err := c.newReq(ctx, "POST", c.Host+"/api/spex/upload/"+sha1,
		guard.body(f))
	if err != nil {
		return ticloudResult{err: c.reqErr(err)}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = fi.Size()
	c.paceSpex()
	cl := *c.upHC
	cl.CheckRedirect = checkNoRedirect // never follow: creds/body would leak
	resp, err := cl.Do(req)
	if err != nil {
		return ticloudResult{err: c.reqErr(guard.err(ctx, err))}
	}
	defer resp.Body.Close()
	b := guard.readResponse(resp.Body, 4<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ticloudResult{status: resp.StatusCode,
			err: fmt.Sprintf("http_%d: %s", resp.StatusCode,
				c.errText(b))}
	}
	return ticloudResult{status: resp.StatusCode, ok: true}
}

// UploadMeta POSTs the metadata XML to /api/spex/upload/{sha1}/meta
// (Content-Type application/octet-stream per the API contract). Safe to
// retry alone once the binary is stored under the sha1.
func (c *TicloudClient) UploadMeta(sha1, filename, domain,
	archivePassword string) ticloudResult {
	sha1 = strings.ToLower(sha1)
	if !isA1000SHA1(sha1) {
		return ticloudResult{err: "invalid sha1"}
	}
	body := ticloudMetaXML(filename, domain, archivePassword)
	ctx, guard, release := newIdleGuard(c.uploadTimeout)
	defer release()
	req, err := c.newReq(ctx, "POST",
		c.Host+"/api/spex/upload/"+sha1+"/meta",
		guard.body(strings.NewReader(body)))
	if err != nil {
		return ticloudResult{err: c.reqErr(err)}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) { // keep stale-conn retry
		return guard.body(strings.NewReader(body)), nil
	}
	c.paceSpex()
	cl := *c.upHC
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return ticloudResult{err: c.reqErr(guard.err(ctx, err))}
	}
	defer resp.Body.Close()
	b := guard.readResponse(resp.Body, 4<<20)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ticloudResult{status: resp.StatusCode,
			err: fmt.Sprintf("http_%d: %s", resp.StatusCode,
				c.errText(b))}
	}
	return ticloudResult{status: resp.StatusCode, ok: true}
}

// SubmitSample runs the two-step spex submit in order — binary POST then
// metadata POST. If the meta POST fails after a successful binary upload
// the sample is already stored under its sha1: err is prefixed
// "meta_failed:" and a retry must pass sampleUploaded=true so only the
// meta step is re-posted (binary already stored).
func (c *TicloudClient) SubmitSample(sha1, filePath, filename, domain,
	archivePassword string, sampleUploaded bool) ticloudResult {
	if !sampleUploaded {
		res := c.UploadSample(sha1, filePath)
		if res.err != "" {
			return res
		}
	}
	if filename == "" {
		filename = filepath.Base(filePath)
	}
	res := c.UploadMeta(sha1, filename, domain, archivePassword)
	if res.err != "" {
		res.err = "meta_failed: " + res.err
		return res
	}
	return res
}

// extStr renders the ?extended= query flag for reputation endpoints.
func (c *TicloudClient) extStr() string {
	if c.extended {
		return "true"
	}
	return "false"
}

// ReputationBulk POSTs /api/databrowser/malware_presence/bulk_query/json
// ?extended={cfg} chunked at ticloudReputationChunk (API max 100) ->
// (status, entries, invalidHashes, err). One failing chunk fails the whole
// call. entries carry the raw extended fields (status, threat_name,
// threat_level, trust_factor, scanner_*); invalidHashes are returned
// verbatim for the caller to log+count.
func (c *TicloudClient) ReputationBulk(hashes []string,
	hashType string) (int, []map[string]any, []any, string) {
	hashType = strings.ToLower(hashType)
	if !ticloudHashTypes[hashType] {
		return 0, nil, nil,
			fmt.Sprintf("invalid hash_type %q", hashType)
	}
	var entries []map[string]any
	var invalid []any
	lastStatus := 0
	for i := 0; i < len(hashes); i += ticloudReputationChunk {
		end := i + ticloudReputationChunk
		if end > len(hashes) {
			end = len(hashes)
		}
		payload, _ := json.Marshal(map[string]any{"rl": map[string]any{
			"query": map[string]any{
				"hash_type": hashType, "hashes": hashes[i:end]}}})
		ctx, cancel := context.WithTimeout(context.Background(),
			ticloudQueryTimeout)
		req, err := c.newReq(ctx, "POST",
			c.Host+"/api/databrowser/malware_presence/bulk_query/json"+
				"?extended="+c.extStr(), bytes.NewReader(payload))
		if err != nil {
			cancel()
			return 0, nil, nil, c.reqErr(err)
		}
		req.Header.Set("Content-Type", "application/json")
		cl := *c.hc
		cl.CheckRedirect = checkNoRedirect
		resp, err := cl.Do(req)
		if err != nil {
			cancel()
			return 0, nil, nil, c.reqErr(err)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		cancel()
		lastStatus = resp.StatusCode
		if resp.StatusCode != 200 {
			return resp.StatusCode, nil, nil, fmt.Sprintf("http_%d: %s",
				resp.StatusCode, c.errText(b))
		}
		var body map[string]any
		if err := json.Unmarshal(b, &body); err != nil {
			return resp.StatusCode, nil, nil,
				"invalid reputation response body"
		}
		rl, ok := body["rl"].(map[string]any)
		if !ok {
			return resp.StatusCode, nil, nil,
				"invalid reputation response body"
		}
		ents := ticloudList(rl["entries"])
		inv := ticloudList(rl["invalid_hashes"])
		if rl["entries"] != nil && ents == nil ||
			rl["invalid_hashes"] != nil && inv == nil {
			return resp.StatusCode, nil, nil,
				"invalid reputation response body"
		}
		for _, e := range ents {
			if m, ok := e.(map[string]any); ok {
				entries = append(entries, m)
			}
		}
		invalid = append(invalid, inv...)
	}
	return lastStatus, entries, invalid, ""
}

// ReputationSingle GETs /api/databrowser/malware_presence/query/
// {hash_type}/{h}?extended={cfg} -> (status, entry, err). entry is the
// single rl.entry dict (or rl.entries[0]) — same raw shape as bulk entries.
func (c *TicloudClient) ReputationSingle(hashValue,
	hashType string) (int, map[string]any, string) {
	hashType = strings.ToLower(hashType)
	hashValue = strings.ToLower(hashValue)
	if !ticloudHashTypes[hashType] {
		return 0, nil, fmt.Sprintf("invalid hash_type %q", hashType)
	}
	if !isA1000Hash(hashValue) { // hex 32/40/64/128 — same validator as A1000
		return 0, nil, "invalid hash"
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		ticloudQueryTimeout)
	defer cancel()
	req, err := c.newReq(ctx, "GET",
		c.Host+"/api/databrowser/malware_presence/query/"+hashType+"/"+
			hashValue+"?extended="+c.extStr(), nil)
	if err != nil {
		return 0, nil, c.reqErr(err)
	}
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, c.reqErr(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil, fmt.Sprintf("http_%d: %s",
			resp.StatusCode, c.errText(b))
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		return resp.StatusCode, nil, "invalid reputation response body"
	}
	rl, ok := body["rl"].(map[string]any)
	if !ok {
		return resp.StatusCode, nil, "invalid reputation response body"
	}
	if ent, ok := rl["entry"].(map[string]any); ok {
		return resp.StatusCode, ent, ""
	}
	if ents := ticloudList(rl["entries"]); len(ents) > 0 {
		if ent, ok := ents[0].(map[string]any); ok {
			return resp.StatusCode, ent, ""
		}
	}
	return resp.StatusCode, nil, "no entry in response"
}
