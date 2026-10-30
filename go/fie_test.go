// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fieTestServer mimics the FIE endpoints: /readyz, /check-sample/hash/sha1/{h},
// POST /scan. hashBody/hashCode answer check-sample; scanBody/scanCode answer
// scan (may be a handler for sequence tests).
type fieTestServer struct {
	srv *httptest.Server

	checkCalls, scanCalls, readyCalls *int32
	externalID                        *string
	lastScanBody                      *[]byte

	hashCode int
	hashBody string
	scanFn   http.HandlerFunc
}

func newFieTestServer(t *testing.T, hashCode int, hashBody,
	scanBody string) (*fieTestServer, *FieBackend) {
	t.Helper()
	s := &fieTestServer{hashCode: hashCode, hashBody: hashBody,
		checkCalls: new(int32), scanCalls: new(int32), readyCalls: new(int32),
		externalID: new(string), lastScanBody: new([]byte)}
	s.scanFn = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, scanBody)
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		switch {
		case r.URL.Path == "/readyz":
			atomic.AddInt32(s.readyCalls, 1)
			w.WriteHeader(200)
		case r.Method == "GET" &&
			strings.HasPrefix(r.URL.Path, "/check-sample/hash/sha1/"):
			atomic.AddInt32(s.checkCalls, 1)
			w.WriteHeader(s.hashCode)
			fmt.Fprint(w, s.hashBody)
		case r.Method == "POST" && r.URL.Path == "/scan":
			atomic.AddInt32(s.scanCalls, 1)
			*s.externalID = r.URL.Query().Get("external_id")
			buf, _ := io.ReadAll(r.Body)
			*s.lastScanBody = buf
			if cl := r.Header.Get("Content-Length"); cl == "" {
				t.Error("scan POST missing Content-Length")
			}
			s.scanFn(w, r)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.srv.Close)
	b := NewFieBackend(NewFieClient(s.srv.URL, true, ""),
		"hash_then_scan", false, "rel_path")
	return s, b
}

func testArgs() *Args {
	return &Args{BackoffBase: 0, BackoffMax: 0, UploadRetryWindow: 30,
		MaxUploadAttempts: 3, ReadyCheckInterval: 0, ReadyMaxWait: 0,
		AvailProbeSeconds: 0}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFieBackendInterface(t *testing.T) {
	var _ ScanBackend = (*FieBackend)(nil)
}

func TestFieBackendAttrsAndProbe(t *testing.T) {
	s, b := newFieTestServer(t, 200, `{"classification":"OK"}`, `{}`)
	if b.Name() != "fie" || !b.NeedsSHA1() || !b.IsSync() {
		t.Fatalf("bad attrs: %s %v %v", b.Name(), b.NeedsSHA1(), b.IsSync())
	}
	if !b.Probe(2 * time.Second) {
		t.Fatal("probe should hit readyz 200")
	}
	if *s.readyCalls == 0 {
		t.Fatal("probe never reached /readyz")
	}
}

func TestFieScanModeVerdict(t *testing.T) {
	s, b := newFieTestServer(t, 200, `{"classification":"OK"}`,
		`{"classification":"malicious","threat_details":`+
			`{"threat_name":"Win32.Evil","scanner_match":37}}`)
	b.mode = "scan"
	f := writeFile(t, "a.bin", "MZpayload")
	o := b.SubmitOnce(f, "s256", "abcsha1",
		map[string]any{"rel_path": "usb/a.bin"})
	if o.Kind != "verdict" || o.Classification == nil ||
		*o.Classification != "malicious" {
		t.Fatalf("bad outcome: %+v", o)
	}
	if o.ThreatName == nil || *o.ThreatName != "Win32.Evil" {
		t.Fatalf("bad threat_name: %+v", o.ThreatName)
	}
	if o.ThreatFactor == nil || *o.ThreatFactor != 37 {
		t.Fatalf("bad threat_factor: %+v", o.ThreatFactor)
	}
	if o.ReportJSON == nil || *o.ReportJSON == "" {
		t.Fatal("report_json must carry the raw response")
	}
	if *s.scanCalls != 1 || *s.checkCalls != 0 {
		t.Fatalf("scan mode must POST /scan only: scan=%d check=%d",
			*s.scanCalls, *s.checkCalls)
	}
	if *s.externalID != "usb/a.bin" {
		t.Fatalf("external_id want usb/a.bin, got %q", *s.externalID)
	}
	if string(*s.lastScanBody) != "MZpayload" {
		t.Fatalf("raw body mismatch: %q", *s.lastScanBody)
	}
}

func TestFieExternalIDModes(t *testing.T) {
	s, b := newFieTestServer(t, 200, `{}`, `{"classification":"OK"}`)
	b.mode = "scan"
	f := writeFile(t, "real.bin", "x")

	b.externalID = "filename"
	b.SubmitOnce(f, "s", "abcsha1", map[string]any{"rel_path": "a/b/real.bin"})
	if *s.externalID != "real.bin" {
		t.Fatalf("filename mode: got %q", *s.externalID)
	}

	b.externalID = "none"
	b.SubmitOnce(f, "s", "abcsha1", map[string]any{"rel_path": "a/b/real.bin"})
	if *s.externalID != "" {
		t.Fatalf("none mode: got %q", *s.externalID)
	}

	b.externalID = "rel_path"
	b.SubmitOnce(f, "s", "abcsha1", nil) // no meta -> basename fallback
	if *s.externalID != "real.bin" {
		t.Fatalf("rel_path fallback: got %q", *s.externalID)
	}
}

func TestFieHashThenScanMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, hashBody string
		trustOK        bool
		wantCls        string
		wantScanCalls  int32
	}{
		{"malicious", `{"classification":"malicious","threat_details":{"threat_name":"X"}}`,
			false, "malicious", 0},
		{"suspicious", `{"classification":"suspicious"}`,
			false, "suspicious", 0},
		{"ok-untrusted-scans", `{"classification":"OK"}`,
			false, "malicious", 1},
		{"ok-trusted", `{"classification":"OK"}`,
			true, "goodware", 0},
		{"unrecognized-scans", `{"classification":"wat"}`,
			false, "malicious", 1},
	} {
		s, b := newFieTestServer(t, 200, tc.hashBody,
			`{"classification":"malicious"}`)
		b.mode = "hash_then_scan"
		b.trustOK = tc.trustOK
		f := writeFile(t, "a.bin", "x")
		o := b.SubmitOnce(f, "s256", "abcsha1", nil)
		if o.Kind != "verdict" || o.Classification == nil ||
			*o.Classification != tc.wantCls {
			t.Fatalf("%s: bad outcome %+v", tc.name, o)
		}
		if *s.scanCalls != tc.wantScanCalls {
			t.Fatalf("%s: scanCalls=%d want %d", tc.name,
				*s.scanCalls, tc.wantScanCalls)
		}
	}
}

func TestFieHashOnlyMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, hashBody string
		trustOK        bool
		wantCls        string
	}{
		{"malicious", `{"classification":"malicious"}`, false, "malicious"},
		{"suspicious", `{"classification":"suspicious"}`, false, "suspicious"},
		{"ok-untrusted", `{"classification":"OK"}`, false, "unknown"},
		{"ok-trusted", `{"classification":"OK"}`, true, "goodware"},
		{"unrecognized", `{"classification":"huh"}`, false, "unknown"},
	} {
		s, b := newFieTestServer(t, 200, tc.hashBody, `{}`)
		b.mode = "hash_only"
		b.trustOK = tc.trustOK
		f := writeFile(t, "a.bin", "x")
		o := b.SubmitOnce(f, "s256", "abcsha1", nil)
		if o.Kind != "verdict" || o.Classification == nil ||
			*o.Classification != tc.wantCls {
			t.Fatalf("%s: bad outcome %+v", tc.name, o)
		}
		if *s.scanCalls != 0 {
			t.Fatalf("%s: hash_only must never POST /scan", tc.name)
		}
	}
	// ambiguous OK must keep the raw response
	_, b := newFieTestServer(t, 200, `{"classification":"OK"}`, `{}`)
	b.mode = "hash_only"
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitOnce(f, "s256", "abcsha1", nil)
	if o.ReportJSON == nil || *o.ReportJSON != `{"classification":"OK"}` {
		t.Fatalf("report_json must carry raw response, got %v", o.ReportJSON)
	}
}

func TestFieScanErrorIsOutcome(t *testing.T) {
	s, b := newFieTestServer(t, 200, `{}`, `{}`)
	b.mode = "scan"
	s.scanFn = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, "too big")
	}
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitOnce(f, "s256", "abcsha1", nil)
	if o.Kind != "error" || o.HTTPStatus == nil || *o.HTTPStatus != 400 {
		t.Fatalf("bad outcome: %+v", o)
	}
}

func TestFiePermanentNoRetry(t *testing.T) {
	for _, code := range []int{400, 413} {
		s, b := newFieTestServer(t, 200, `{}`, `{}`)
		b.mode = "scan"
		c := code
		s.scanFn = func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c)
		}
		f := writeFile(t, "a.bin", "x")
		o := b.SubmitWithBackoff(f, "s256", "abcsha1", nil, testArgs(), nil)
		if o.Kind != "error" || *o.HTTPStatus != c {
			t.Fatalf("%d: bad outcome %+v", code, o)
		}
		if *s.scanCalls != 1 {
			t.Fatalf("%d permanent must not retry: %d calls", code,
				*s.scanCalls)
		}
	}
}

func TestFieRetriableThenVerdict(t *testing.T) {
	for _, code := range []int{429, 524, 503} {
		s, b := newFieTestServer(t, 200, `{}`, `{}`)
		b.mode = "scan"
		c := code
		var n int32
		s.scanFn = func(w http.ResponseWriter, r *http.Request) {
			if atomic.AddInt32(&n, 1) == 1 {
				w.WriteHeader(c)
				return
			}
			w.WriteHeader(200)
			fmt.Fprint(w, `{"classification":"suspicious"}`)
		}
		f := writeFile(t, "a.bin", "x")
		o := b.SubmitWithBackoff(f, "s256", "abcsha1", nil, testArgs(), nil)
		if o.Kind != "verdict" || *o.Classification != "suspicious" {
			t.Fatalf("%d: bad outcome %+v", code, o)
		}
		if atomic.LoadInt32(&n) != 2 {
			t.Fatalf("%d: want 2 scan attempts, got %d", code, n)
		}
	}
}

func TestFieErrorMarksUnavailable(t *testing.T) {
	s, b := newFieTestServer(t, 200, `{}`, `{}`)
	b.mode = "scan"
	s.scanFn = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}
	f := writeFile(t, "a.bin", "x")
	b.SubmitWithBackoff(f, "s256", "abcsha1", nil,
		&Args{BackoffBase: 0, BackoffMax: 0, UploadRetryWindow: 0,
			MaxUploadAttempts: 1, ReadyCheckInterval: 0, ReadyMaxWait: 0,
			AvailProbeSeconds: 60}, nil)
	// 5xx stamps the shared cache: a second worker's AvailableNow within TTL
	// must gate WITHOUT probing again.
	before := atomic.LoadInt32(s.readyCalls)
	if b.client.AvailableNow(60 * time.Second) {
		t.Fatal("cache should be False after 5xx")
	}
	if atomic.LoadInt32(s.readyCalls) != before {
		t.Fatal("AvailableNow must not re-probe inside TTL")
	}
}

func TestFiePollBatchUnused(t *testing.T) {
	_, b := newFieTestServer(t, 200, `{}`, `{}`)
	if got := b.PollBatch([]PollRef{{Ref: "x"}}); len(got) != 0 {
		t.Fatalf("PollBatch unused: got %v", got)
	}
}

func TestMakeBackendFie(t *testing.T) {
	b, err := makeBackend(&Args{Backend: "fie", FieHost: "http://fie.local/",
		FieMode: "scan", FieExternalID: "none"})
	if err != nil || b == nil || b.Name() != "fie" {
		t.Fatalf("fie: %v %+v", err, b)
	}
	fb, ok := b.(*FieBackend)
	if !ok || fb.client.Host != "http://fie.local" {
		t.Fatalf("bad fie backend: %+v", b)
	}
	if _, err := makeBackend(&Args{Backend: "fie"}); err == nil {
		t.Fatal("missing fie.host should error")
	}
}
