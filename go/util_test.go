// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// util_test.go — mirror of tests/test_read_hash.py: sha1 is opt-in and
// produced in the same streaming pass.
package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReadHashCaptureSHA1(t *testing.T) {
	// FIE/cloud backends address samples by sha1, detect/a1000 do not — the
	// extra hasher is opt-in so the default path stays sha256-only.
	data := bytes.Repeat([]byte("hello world"), 1000)
	p := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}

	d, s1, head, total := readHashCapture(p, 4, false)
	if d != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Errorf("sha256 mismatch")
	}
	if s1 != "" {
		t.Errorf("sha1 computed when not requested: %q", s1)
	}
	if !bytes.Equal(head, data[:4]) || total != int64(len(data)) {
		t.Errorf("head/total mismatch")
	}

	d, s1, _, _ = readHashCapture(p, 4, true)
	if d != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Errorf("sha256 mismatch")
	}
	if s1 != fmt.Sprintf("%x", sha1.Sum(data)) {
		t.Errorf("sha1 mismatch")
	}
}

func TestAlerterWebhookNoRedirect(t *testing.T) {
	// A 302 must surface as a failed delivery, never be followed — a
	// redirect would re-POST the alert payload to a foreign host.
	var followed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/hook" {
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(http.StatusFound)
				return
			}
			followed.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
	defer srv.Close()

	var buf bytes.Buffer
	a := NewAlerter(map[string]bool{"malicious": true}, "",
		srv.URL+"/hook", nil, false, &Logger{out: &buf})
	a.toWebhook(map[string]any{"classification": "malicious"})

	if got := followed.Load(); got != 0 {
		t.Fatalf("redirect target hit %d time(s) — redirect was followed", got)
	}
	if !strings.Contains(buf.String(), "ERROR") {
		t.Fatalf("302 not logged as a webhook failure: %q", buf.String())
	}
}

// Only the file_types filter consumes the head, and only head[:4096]
// (mirrors Python HEAD_CAPTURE_BYTES): extract_* never triggers capture.
func TestHeadCaptureBytes(t *testing.T) {
	a := &Args{MaxEnrichBytes: DefaultMaxEnrichBytes}
	if n := headCaptureBytes(a, 1<<30); n != 0 {
		t.Fatalf("no file_types: want 0, got %d", n)
	}
	a.ExtractStrings, a.ExtractIOCs = true, true
	if n := headCaptureBytes(a, 1<<30); n != 0 {
		t.Fatalf("extract_* alone must not capture: got %d", n)
	}
	a.FileTypesSet = map[string]bool{"pe": true}
	if n := headCaptureBytes(a, 1<<30); n != 4096 {
		t.Fatalf("want 4096 cap, got %d", n)
	}
	if n := headCaptureBytes(a, 100); n != 100 {
		t.Fatalf("small file: want 100, got %d", n)
	}
}
