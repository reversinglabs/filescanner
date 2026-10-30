// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// detectTestServer mimics the Worker endpoints the adapter touches:
// /readyz, /api/tiscale/v1/upload (returns task_url), /task/{n} status.
func detectTestServer(t *testing.T, taskBody string,
	taskCode int) (*httptest.Server, *DetectBackend) {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		switch {
		case r.URL.Path == "/readyz":
			w.WriteHeader(200)
		case r.Method == "POST" && r.URL.Path == "/api/tiscale/v1/upload":
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"task_url": "%s/task/1"}`, srv.URL)
		case r.Method == "GET" && r.URL.Path == "/task/1":
			w.WriteHeader(taskCode)
			fmt.Fprint(w, taskBody)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	b := NewDetectBackend(NewDetectAsyncClient(srv.URL, "tok", true, ""))
	return srv, b
}

func TestDetectBackendInterface(t *testing.T) {
	var _ ScanBackend = (*DetectBackend)(nil)
}

func TestDetectBackendAttrsAndProbe(t *testing.T) {
	_, b := detectTestServer(t, "{}", 200)
	if b.Name() != "detect" || b.NeedsSHA1() || b.IsSync() {
		t.Fatalf("bad attrs: %s %v %v", b.Name(), b.NeedsSHA1(), b.IsSync())
	}
	if !b.Probe(2 * time.Second) {
		t.Fatal("probe should hit readyz 200")
	}
}

func TestDetectBackendSubmitOnceReceipt(t *testing.T) {
	srv, b := detectTestServer(t, "{}", 200)
	f := filepath.Join(t.TempDir(), "a.bin")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := b.SubmitOnce(f, "s256", "", map[string]any{"k": "v"})
	if o.Kind != "receipt" || o.Ref != srv.URL+"/task/1" {
		t.Fatalf("bad outcome: %+v", o)
	}
	if o.HTTPStatus == nil || *o.HTTPStatus != 201 {
		t.Fatalf("want http_status 201, got %+v", o.HTTPStatus)
	}
}

func TestDetectBackendSubmitOnceError(t *testing.T) {
	_, b := detectTestServer(t, "{}", 200)
	o := b.SubmitOnce(filepath.Join(t.TempDir(), "missing.bin"),
		"s256", "", nil)
	if o.Kind != "error" || o.Error == nil {
		t.Fatalf("bad outcome: %+v", o)
	}
}

func TestDetectBackendPollBatchStates(t *testing.T) {
	report := `{"processed":1,"tc_report":[{"classification":` +
		`{"classification":3,"factor":7,"result":"Win32.Evil"}}]}`
	srv, b := detectTestServer(t, report, 200)
	out := b.PollBatch([]PollRef{
		{Ref: srv.URL + "/task/1"},
		{Ref: srv.URL + "/task/404"}, // hits default 404 -> gone
	})
	v, ok := out[srv.URL+"/task/1"].(map[string]any)
	if !ok {
		t.Fatalf("want verdict map, got %v", out[srv.URL+"/task/1"])
	}
	if v["classification"] != "malicious" ||
		v["threat_name"] != "Win32.Evil" {
		t.Fatalf("bad verdict: %+v", v)
	}
	if f, _ := v["threat_factor"].(*int64); f == nil || *f != 7 {
		t.Fatalf("bad threat_factor: %+v", v["threat_factor"])
	}
	if out[srv.URL+"/task/404"] != "gone" {
		t.Fatalf("want gone, got %v", out[srv.URL+"/task/404"])
	}
}

func TestDetectBackendPollBatchPending(t *testing.T) {
	srv, b := detectTestServer(t, `{"processed":0}`, 200)
	out := b.PollBatch([]PollRef{{Ref: srv.URL + "/task/1"}})
	if out[srv.URL+"/task/1"] != "pending" {
		t.Fatalf("want pending, got %v", out)
	}
}

func TestMakeBackend(t *testing.T) {
	b, err := makeBackend(&Args{Backend: "detect", Host: "https://h"})
	if err != nil || b == nil || b.Name() != "detect" {
		t.Fatalf("detect: %v %+v", err, b)
	}
	for _, name := range []string{"a1000", "cloud"} {
		if _, err := makeBackend(&Args{Backend: name}); err == nil {
			t.Fatalf("%s should error (not yet supported)", name)
		}
	}
	if _, err := makeBackend(&Args{Backend: "bogus"}); err == nil {
		t.Fatal("unknown backend should error")
	}
}
