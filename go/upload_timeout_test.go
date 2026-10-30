// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Upload timeouts mirror Python requests timeout=(30, N): no whole-request
// deadline, only a per-I/O inactivity window. A large upload that keeps
// progressing must succeed however long it takes; a stalled one must abort
// after the inactivity window.

const uploadTestBodySize = 16 << 20 // larger than loopback socket buffers

func bigUploadFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(p, make([]byte, uploadTestBodySize), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

type uploadCase struct {
	name string
	// reply writes the backend's success response.
	reply func(w http.ResponseWriter, srvURL string)
	// run builds a client against url with the given inactivity window and
	// response-header timeout, performs one upload and returns its error.
	run func(url, file string, idle, header time.Duration) string
}

func setHeaderTimeout(hc *http.Client, d time.Duration) {
	hc.Transport.(*http.Transport).ResponseHeaderTimeout = d
}

var uploadCases = []uploadCase{
	{
		name: "detect",
		reply: func(w http.ResponseWriter, u string) {
			json.NewEncoder(w).Encode(map[string]any{
				"task_url": u + "/api/tiscale/v1/task/1"})
		},
		run: func(u, f string, idle, header time.Duration) string {
			c := NewDetectAsyncClient(u, "tok", true, "")
			c.uploadIdle = idle
			setHeaderTimeout(c.hc, header)
			return c.UploadOnce(f, nil).err
		},
	},
	{
		name: "a1000",
		reply: func(w http.ResponseWriter, _ string) {
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{
				"sha1": strings.Repeat("a", 40)}})
		},
		run: func(u, f string, idle, header time.Duration) string {
			c := NewA1000Client(u, "tok", true, "")
			c.uploadIdle = idle
			setHeaderTimeout(c.hc, header)
			return c.Upload(f, nil).err
		},
	},
	{
		name: "fie",
		reply: func(w http.ResponseWriter, _ string) {
			w.Write([]byte(`{"classification":"OK"}`))
		},
		run: func(u, f string, idle, header time.Duration) string {
			c := NewFieClient(u, true, "")
			c.uploadIdle = idle
			setHeaderTimeout(c.hc, header)
			return c.ScanFile(f, "").err
		},
	},
	{
		name: "ticloud",
		reply: func(w http.ResponseWriter, _ string) {
			w.WriteHeader(201)
		},
		run: func(u, f string, idle, header time.Duration) string {
			c := NewTicloudClient(u, "tcuser", "tcpass", true, "", idle, 0, false)
			setHeaderTimeout(c.upHC, header)
			return c.UploadSample(strings.Repeat("b", 40), f).err
		},
	},
}

// TestUploadSlowButSteadySucceeds: the server drains the body slowly but
// steadily for ~4x the inactivity window — under a whole-request deadline
// of that window it would fail; with per-read inactivity it succeeds.
func TestUploadSlowButSteadySucceeds(t *testing.T) {
	file := bigUploadFile(t)
	const idle = 400 * time.Millisecond
	for _, tc := range uploadCases {
		t.Run(tc.name, func(t *testing.T) {
			var srvURL string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					buf := make([]byte, 512<<10)
					for {
						_, err := io.ReadFull(r.Body, buf)
						if err != nil {
							break
						}
						time.Sleep(50 * time.Millisecond)
					}
					tc.reply(w, srvURL)
				}))
			defer srv.Close()
			srvURL = srv.URL
			start := time.Now()
			if e := tc.run(srv.URL, file, idle, 10*time.Second); e != "" {
				t.Fatalf("slow-but-steady upload failed after %s: %s",
					time.Since(start), e)
			}
			if el := time.Since(start); el < 2*idle {
				t.Fatalf("upload finished in %s — test did not exceed the "+
					"inactivity window, so it proves nothing", el)
			}
		})
	}
}

// TestUploadStallAbortsAfterInactivity: the server stops reading the body
// (and never answers); the upload must abort after the inactivity window,
// not wait for the (large) response-header timeout.
func TestUploadStallAbortsAfterInactivity(t *testing.T) {
	file := bigUploadFile(t)
	const idle = 300 * time.Millisecond
	for _, tc := range uploadCases {
		t.Run(tc.name, func(t *testing.T) {
			unblock := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					<-unblock
				}))
			t.Cleanup(srv.Close)
			t.Cleanup(func() { close(unblock) }) // runs before srv.Close
			start := time.Now()
			e := tc.run(srv.URL, file, idle, 30*time.Second)
			el := time.Since(start)
			if e == "" {
				t.Fatal("stalled upload unexpectedly succeeded")
			}
			if el > 5*time.Second {
				t.Fatalf("stalled upload took %s to abort (idle=%s): %s",
					el, idle, e)
			}
			if !strings.Contains(e, "read timeout") {
				t.Fatalf("want a read-timeout error, got %q", e)
			}
		})
	}
}

// TestUploadResponseHeaderTimeout: body fully sent, server never answers —
// the per-backend read timeout (ResponseHeaderTimeout) bounds the wait.
func TestUploadResponseHeaderTimeout(t *testing.T) {
	p := filepath.Join(t.TempDir(), "small.bin")
	os.WriteFile(p, []byte("hello"), 0o644)
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			<-unblock
		}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(unblock) })
	start := time.Now()
	e := uploadCases[0].run(srv.URL, p, 30*time.Second, 300*time.Millisecond)
	if e == "" || time.Since(start) > 5*time.Second {
		t.Fatalf("want header-timeout failure promptly, got %q after %s",
			e, time.Since(start))
	}
}

// TestUploadTimeoutDefaults pins the per-backend read timeouts to Python's
// timeout=(30, N) values and the 30s connect/TLS bounds.
func TestUploadTimeoutDefaults(t *testing.T) {
	d := NewDetectAsyncClient("http://x", "t", true, "")
	a := NewA1000Client("http://x", "t", true, "")
	f := NewFieClient("http://x", true, "")
	tc := NewTicloudClient("http://x", "u", "p", true, "", 123*time.Second, 0, false)
	for _, c := range []struct {
		name string
		idle time.Duration
		hc   *http.Client
		want time.Duration
	}{
		{"detect", d.uploadIdle, d.hc, 300 * time.Second},
		{"a1000", a.uploadIdle, a.hc, 300 * time.Second},
		{"fie", f.uploadIdle, f.hc, 600 * time.Second},
		{"ticloud", tc.uploadTimeout, tc.upHC, 123 * time.Second},
	} {
		tr := c.hc.Transport.(*http.Transport)
		if c.idle != c.want || tr.ResponseHeaderTimeout != c.want {
			t.Errorf("%s: idle=%s header=%s want %s", c.name, c.idle,
				tr.ResponseHeaderTimeout, c.want)
		}
		if tr.TLSHandshakeTimeout != 30*time.Second || tr.DialContext == nil {
			t.Errorf("%s: connect/TLS timeouts not set", c.name)
		}
		if c.name == "ticloud" &&
			tc.hc.Transport.(*http.Transport).ResponseHeaderTimeout != 0 {
			t.Errorf("ticloud query transport must not inherit upload_timeout")
		}
		if c.hc.Timeout != 0 {
			t.Errorf("%s: whole-request client timeout must be unset", c.name)
		}
	}
}
