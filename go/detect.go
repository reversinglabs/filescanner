// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// detect.go — async Spectra Detect client: submit → task_url, poll task_url.
// Mirrors DetectAsyncClient: shared availability cache, fresh-False gating,
// wait_ready recovery propagation, exp backoff, same-origin task_url guard,
// streaming multipart upload with explicit Content-Length.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// detectUploadReadTimeout mirrors Python upload timeout=(30, 300).
const detectUploadReadTimeout = 300 * time.Second

// detectPermanentStatuses: upload outcomes that can never succeed on retry
// — no backoff, no mark-unavailable (like the FIE/A1000 permanent sets).
var detectPermanentStatuses = map[int]bool{400: true, 413: true}

var errTaskGone = errors.New("task record lost (404)")

// Upload outcomes that can never succeed on retry.
var nonRetriableUploadErrors = map[string]bool{
	"invalid task_url":               true,
	"task_url cross-origin rejected": true,
	"invalid upload response body":   true,
}

type DetectAsyncClient struct {
	Host     string
	ReadyURL string
	hc       *http.Client
	token    string
	// uploadIdle is the upload read timeout N of Python timeout=(30, N).
	uploadIdle time.Duration

	availMu sync.Mutex
	availOK bool
	availAt time.Time
}

func NewDetectAsyncClient(host, token string, verifySSL bool, proxy string) *DetectAsyncClient {
	host = strings.TrimRight(host, "/")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL}, //nolint:gosec
		// Explicit config only: HTTP(S)_PROXY env vars must not override the
		// configured proxy setting (mirrors requests trust_env=False).
		Proxy: nil,
	}
	applyUploadTimeouts(tr, detectUploadReadTimeout)
	if proxy != "" {
		if pu, err := url.Parse(proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &DetectAsyncClient{
		Host:       host,
		ReadyURL:   host + "/readyz",
		token:      token,
		hc:         &http.Client{Transport: tr},
		uploadIdle: detectUploadReadTimeout,
		availOK:    true,
	}
}

func (c *DetectAsyncClient) newReq(ctx context.Context, method, rawURL string,
	body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+c.token)
	return req, nil
}

// The API never legitimately redirects; don't follow (no re-POST of body/auth).
var checkNoRedirect = func(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

// errText renders a response body for an error string — the token is redacted
// even if the appliance echoes request headers back.
func (c *DetectAsyncClient) errText(b []byte) string {
	t := string(b)
	if len(t) > 200 {
		t = t[:200]
	}
	if c.token != "" {
		t = strings.ReplaceAll(t, c.token, "***")
	}
	return t
}

func (c *DetectAsyncClient) isReady(timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := c.newReq(ctx, "GET", c.ReadyURL, nil)
	if err != nil {
		return false
	}
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return false
	}
	code := resp.StatusCode
	resp.Body.Close()
	if code == 404 {
		// Older receivers expose availability under /srv.
		ctx2, cancel2 := context.WithTimeout(context.Background(), timeout)
		defer cancel2()
		req2, err := c.newReq(ctx2, "GET",
			c.Host+"/srv/tiscale/v1/available", nil)
		if err != nil {
			return false
		}
		resp2, err := cl.Do(req2)
		if err != nil {
			return false
		}
		code = resp2.StatusCode
		resp2.Body.Close()
	}
	return code == 200
}

func (c *DetectAsyncClient) WaitReady(maxWait, interval time.Duration,
	log *Logger) bool {
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if c.isReady(8 * time.Second) {
			c.availMu.Lock() // propagate recovery to all workers
			c.availOK = true
			c.availAt = time.Now()
			c.availMu.Unlock()
			return true
		}
		if log != nil {
			log.Warn("Detect not ready (%s); rechecking in %s",
				c.ReadyURL, interval)
		}
		time.Sleep(interval)
	}
	return false
}

// AvailableNow: shared cached probe — at most one readyz/available GET per
// ttl across all workers. Fresh-False gates every worker without probing.
func (c *DetectAsyncClient) AvailableNow(ttl time.Duration) bool {
	c.availMu.Lock()
	if time.Since(c.availAt) < ttl {
		ok := c.availOK
		c.availMu.Unlock()
		return ok
	}
	c.availMu.Unlock()
	ok := c.isReady(8 * time.Second)
	c.availMu.Lock()
	c.availAt = time.Now()
	c.availOK = ok
	c.availMu.Unlock()
	return ok
}

// MarkUnavailable stamps a FRESH False so every worker gates for
// avail_probe_seconds without probing.
func (c *DetectAsyncClient) MarkUnavailable() {
	c.availMu.Lock()
	c.availAt = time.Now()
	c.availOK = false
	c.availMu.Unlock()
}

// SameOrigin resolves task_url against the API host and returns it iff it
// lands on the same origin — a foreign URL must never be followed.
func (c *DetectAsyncClient) SameOrigin(taskURL string) (string, bool) {
	if taskURL == "" || strings.Contains(taskURL, "\\") {
		return "", false
	}
	for _, r := range taskURL {
		if r < 0x21 {
			return "", false
		}
	}
	base, err := url.Parse(c.Host + "/")
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(&url.URL{Path: "/"})
	cand, err := url.Parse(taskURL)
	if err != nil {
		return "", false
	}
	resolved = base.ResolveReference(cand)
	if resolved.User != nil || strings.Contains(resolved.Host, "@") {
		return "", false
	}
	portOf := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	same := strings.EqualFold(resolved.Scheme, base.Scheme) &&
		resolved.Hostname() == base.Hostname() && base.Hostname() != "" &&
		portOf(resolved) == portOf(base)
	if !same {
		return "", false
	}
	return resolved.String(), true
}

type uploadResult struct {
	status  int
	taskURL string
	err     string
}

// UploadOnce streams the file as a multipart body with an explicit
// Content-Length (1 MiB chunks — no full-body buffering).
func (c *DetectAsyncClient) UploadOnce(filePath string, customData map[string]any) uploadResult {
	fi, err := os.Stat(filePath)
	if err != nil {
		return uploadResult{err: "file_not_found: " + err.Error()}
	}
	fileSize := fi.Size()
	fname := strings.NewReplacer(`"`, "_", "\r", "", "\n", "").
		Replace(filepath.Base(filePath))
	boundary := "----rlscan" + strings.ReplaceAll(uuid.NewString(), "-", "")
	cj, _ := json.Marshal(customData)
	head := fmt.Sprintf("--%s\r\n"+
		"Content-Disposition: form-data; name=\"custom_data\"\r\n"+
		"\r\n%s\r\n"+
		"--%s\r\n"+
		"Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"+
		"Content-Type: application/octet-stream\r\n\r\n",
		boundary, cj, boundary, fname)
	tail := fmt.Sprintf("\r\n--%s--\r\n", boundary)
	totalLen := int64(len(head)) + fileSize + int64(len(tail))

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if _, err := pw.Write([]byte(head)); err != nil {
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
	req, err := c.newReq(ctx, "POST", c.Host+"/api/tiscale/v1/upload",
		guard.body(pr))
	if err != nil {
		return uploadResult{err: "request_error: " + err.Error()}
	}
	req.Header.Set("Content-Type",
		fmt.Sprintf("multipart/form-data; boundary=%s", boundary))
	req.ContentLength = totalLen
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return uploadResult{err: "request_error: " + guard.err(ctx, err).Error()}
	}
	defer resp.Body.Close()
	body := guard.readResponse(resp.Body, 4<<20)
	code := resp.StatusCode
	if code == 200 || code == 201 {
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return uploadResult{status: code, err: "no task_url in response"}
		}
		tu, _ := parsed["task_url"].(string)
		if tu == "" {
			return uploadResult{status: code, err: "no task_url in response"}
		}
		resolved, ok := c.SameOrigin(tu)
		if !ok {
			if _, isStr := parsed["task_url"].(string); isStr {
				return uploadResult{status: code,
					err: "task_url cross-origin rejected"}
			}
			return uploadResult{status: code, err: "invalid task_url"}
		}
		return uploadResult{status: code, taskURL: resolved}
	}
	return uploadResult{status: code,
		err: fmt.Sprintf("http_%d: %s", code, c.errText(body))}
}

// UploadWithBackoff retries non-2xx/errors with exp backoff; every attempt
// gates on the shared availability cache and parks in WaitReady when down.
func (c *DetectAsyncClient) UploadWithBackoff(filePath string,
	customData map[string]any, a *Args, log *Logger) (taskURL string,
	status int, errStr string, attempts int) {
	deadline := time.Now().Add(time.Duration(a.UploadRetryWindow) * time.Second)
	delay := time.Duration(max(1, a.BackoffBase)) * time.Second
	for attempts < a.MaxUploadAttempts {
		if !c.AvailableNow(time.Duration(a.AvailProbeSeconds) * time.Second) {
			if log != nil {
				log.Warn("Detect not available — pausing upload of %s",
					filepath.Base(filePath))
			}
			c.WaitReady(time.Duration(a.ReadyMaxWait)*time.Second,
				time.Duration(a.ReadyCheckInterval)*time.Second, log)
		}
		attempts++
		res := c.UploadOnce(filePath, customData)
		status, errStr = res.status, res.err
		if res.taskURL != "" {
			return res.taskURL, res.status, "", attempts
		}
		if nonRetriableUploadErrors[res.err] ||
			detectPermanentStatuses[res.status] {
			break // deterministic failure — retries can't help
		}
		c.MarkUnavailable() // non-2xx/error: other workers gate now
		if time.Now().After(deadline) {
			break
		}
		if !c.WaitReady(time.Duration(a.ReadyMaxWait)*time.Second,
			time.Duration(a.ReadyCheckInterval)*time.Second, log) && log != nil {
			log.Warn("readyz gate timed out after %ds; retrying anyway",
				a.ReadyMaxWait)
		}
		wait := delay
		if rem := time.Until(deadline); rem < wait {
			wait = max(0, rem)
		}
		if log != nil {
			log.Warn("upload attempt %d failed (%s); retry in %.0fs",
				attempts, errStr, wait.Seconds())
		}
		time.Sleep(wait)
		delay *= 2
		if mx := time.Duration(a.BackoffMax) * time.Second; delay > mx {
			delay = mx
		}
	}
	return "", status, errStr, attempts
}

// TaskStatus GETs the task record. 404 → errTaskGone (terminal); other
// non-200 / malformed body → transient error (caller unclaims and retries).
func (c *DetectAsyncClient) TaskStatus(taskURL string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := c.newReq(ctx, "GET", taskURL, nil)
	if err != nil {
		return nil, err
	}
	cl := *c.hc
	cl.CheckRedirect = checkNoRedirect
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 404:
		return nil, errTaskGone
	case 200:
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, fmt.Errorf("malformed task body: %v", err)
		}
		return body, nil
	default:
		return nil, fmt.Errorf("task GET %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// DetectBackend — ScanBackend adapter over DetectAsyncClient. Client internals
// untouched: UploadOnce/UploadWithBackoff/TaskStatus keep their semantics.
// ---------------------------------------------------------------------------

type DetectBackend struct{ client *DetectAsyncClient }

func NewDetectBackend(c *DetectAsyncClient) *DetectBackend {
	return &DetectBackend{client: c}
}

func (b *DetectBackend) Name() string     { return "detect" }
func (b *DetectBackend) NeedsSHA1() bool  { return false }
func (b *DetectBackend) IsSync() bool     { return false }
func (b *DetectBackend) MarkUnavailable() { b.client.MarkUnavailable() }

func (b *DetectBackend) Probe(timeout time.Duration) bool {
	return b.client.isReady(timeout)
}

func (b *DetectBackend) WaitReady(maxWait, interval time.Duration,
	log *Logger) bool {
	return b.client.WaitReady(maxWait, interval, log)
}

func (b *DetectBackend) AvailableNow(ttl time.Duration) bool {
	return b.client.AvailableNow(ttl)
}

func (b *DetectBackend) SubmitOnce(filePath, sha256, sha1 string,
	meta map[string]any) SubmitOutcome {
	res := b.client.UploadOnce(filePath, meta)
	if res.taskURL != "" {
		return SubmitOutcome{Kind: "receipt", Ref: res.taskURL,
			HTTPStatus: intOrNil(res.status)}
	}
	return SubmitOutcome{Kind: "error", HTTPStatus: intOrNil(res.status),
		Error: strOrNil(res.err)}
}

func (b *DetectBackend) SubmitWithBackoff(filePath, sha256, sha1 string,
	meta map[string]any, a *Args, log *Logger) SubmitOutcome {
	taskURL, status, errStr, _ := b.client.UploadWithBackoff(
		filePath, meta, a, log)
	if taskURL != "" {
		return SubmitOutcome{Kind: "receipt", Ref: taskURL,
			HTTPStatus: intOrNil(status)}
	}
	return SubmitOutcome{Kind: "error", HTTPStatus: intOrNil(status),
		Error: strOrNil(errStr)}
}

// PollBatch polls each task_url serially — detect has no bulk endpoint.
func (b *DetectBackend) PollBatch(refs []PollRef) map[string]any {
	out := make(map[string]any, len(refs))
	for _, pr := range refs {
		ref := pr.Ref
		if ref == "" {
			continue
		}
		task, err := b.client.TaskStatus(ref)
		switch {
		case errors.Is(err, errTaskGone):
			out[ref] = "gone" // terminal: server purged the task
		case err != nil:
			out[ref] = "pending" // transient; caller unclaims and retries
		case processed(task) == 0:
			out[ref] = "pending"
		default:
			cls, threat, factor := summarizeReport(task)
			var threatAny any
			if threat != "" {
				threatAny = threat
			}
			out[ref] = map[string]any{
				"classification": cls,
				"threat_name":    threatAny,
				"threat_factor":  factor,
				// raw task map — caller decides store_full_report/marshal
				"report_json": task,
			}
		}
	}
	return out
}
