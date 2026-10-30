// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// 400/413 can never succeed on retry: no backoff, no mark-unavailable
// (mirrors Python DETECT_PERMANENT_STATUSES and the FIE/A1000 sets).
func TestDetectUploadPermanentStatusNoRetry(t *testing.T) {
	for _, code := range []int{400, 413} {
		var uploads atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/readyz" {
					return
				}
				uploads.Add(1)
				w.WriteHeader(code)
			}))
		p := filepath.Join(t.TempDir(), "f.bin")
		os.WriteFile(p, []byte("x"), 0o644)
		c := NewDetectAsyncClient(srv.URL, "t", true, "")
		a := &Args{MaxUploadAttempts: 5, UploadRetryWindow: 60,
			BackoffBase: 1, BackoffMax: 1, AvailProbeSeconds: 20,
			ReadyMaxWait: 1, ReadyCheckInterval: 1}
		_, status, errStr, attempts := c.UploadWithBackoff(p, nil, a, nil)
		srv.Close()
		if status != code || attempts != 1 || uploads.Load() != 1 {
			t.Fatalf("%d: status=%d attempts=%d uploads=%d err=%s", code,
				status, attempts, uploads.Load(), errStr)
		}
		c.availMu.Lock()
		ok := c.availOK
		c.availMu.Unlock()
		if !ok {
			t.Fatalf("%d: permanent status must not mark Detect unavailable", code)
		}
	}
}
