// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// CloudBackend adapter tests — mirror tests/test_cloud_backend.py. The
// server scaffold (spex upload/meta, TCA-0101 bulk, probe) is shared with
// ticloud_test.go.

func newCloudBackend(t *testing.T) (*ticloudTestServer, *CloudBackend) {
	t.Helper()
	s, c := newTicloudTestServer(t)
	return s, NewCloudBackend(c, "corp.local", "")
}

func TestCloudBackendInterface(t *testing.T) {
	var _ ScanBackend = (*CloudBackend)(nil)
}

func TestCloudBackendAttrsAndProbe(t *testing.T) {
	s, b := newCloudBackend(t)
	if b.Name() != "cloud" || !b.NeedsSHA1() || b.IsSync() {
		t.Fatalf("bad attrs: %s %v %v", b.Name(), b.NeedsSHA1(), b.IsSync())
	}
	if !b.Probe(2 * time.Second) {
		t.Fatal("probe should hit GET / 200")
	}
	if *s.probeCalls == 0 {
		t.Fatal("probe never reached GET /")
	}
}

// -- submit -----------------------------------------------------------------

func TestCloudSubmitOnceOrderAndReceipt(t *testing.T) {
	s, b := newCloudBackend(t)
	f := writeFile(t, "evil.exe", "MZpayload")
	o := b.SubmitOnce(f, ticloudSHA256, ticloudSHA1, nil)
	if o.Kind != "receipt" || o.Ref != ticloudSHA1 {
		t.Fatalf("bad outcome: %+v", o)
	}
	if o.HTTPStatus == nil || *o.HTTPStatus != 200 {
		t.Fatalf("want http_status 200, got %+v", o.HTTPStatus)
	}
	// binary first, meta second — order matters to the spex pipeline
	if got := *s.order; len(got) != 2 ||
		got[0] != "upload" || got[1] != "meta" {
		t.Fatalf("bad submit order: %v", got)
	}
	meta := string(*s.metaBody)
	if !strings.Contains(meta, "<value>evil.exe</value>") ||
		!strings.Contains(meta, "<domain>corp.local</domain>") {
		t.Fatalf("meta XML missing filename/domain: %s", meta)
	}
}

func TestCloudSubmitOnceArchivePassword(t *testing.T) {
	s, c := newTicloudTestServer(t)
	b := NewCloudBackend(c, "", "in&fected")
	f := writeFile(t, "a.zip", "PK")
	b.SubmitOnce(f, ticloudSHA256, ticloudSHA1, nil)
	if !strings.Contains(string(*s.metaBody),
		"<password>in&amp;fected</password>") {
		t.Fatalf("meta XML missing archive password: %s", *s.metaBody)
	}
}

func TestCloudSubmitOnceBinaryErrorNoMeta(t *testing.T) {
	s, b := newCloudBackend(t)
	s.uploadCode = 500
	s.uploadResp = "down"
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitOnce(f, ticloudSHA256, ticloudSHA1, nil)
	if o.Kind != "error" || o.HTTPStatus == nil || *o.HTTPStatus != 500 {
		t.Fatalf("bad outcome: %+v", o)
	}
	if *s.metaCalls != 0 {
		t.Fatal("meta must not run after a failed binary upload")
	}
}

func TestCloudSubmitOnceMetaFailureFlagged(t *testing.T) {
	s, b := newCloudBackend(t)
	s.metaCode = 503
	s.metaResp = "boom"
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitOnce(f, ticloudSHA256, ticloudSHA1, nil)
	if o.Kind != "error" || o.Error == nil ||
		!strings.HasPrefix(*o.Error, "meta_failed: http_503") {
		t.Fatalf("bad outcome: %+v", o)
	}
}

func TestCloudSubmitOnceInvalidSHA1NoRequest(t *testing.T) {
	s, b := newCloudBackend(t)
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitOnce(f, ticloudSHA256, "not-a-sha1", nil)
	if o.Kind != "error" || o.Error == nil ||
		*o.Error != "invalid sha1" {
		t.Fatalf("bad outcome: %+v", o)
	}
	if *s.uploadCalls != 0 {
		t.Fatal("invalid sha1 must not hit the wire")
	}
}

// -- submit with backoff ------------------------------------------------------

func TestCloudBackoffReceiptFirstTry(t *testing.T) {
	s, b := newCloudBackend(t)
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitWithBackoff(f, ticloudSHA256, ticloudSHA1, nil,
		testArgs(), nil)
	if o.Kind != "receipt" || o.Ref != ticloudSHA1 {
		t.Fatalf("bad outcome: %+v", o)
	}
	if got := *s.order; len(got) != 2 {
		t.Fatalf("want 2 spex posts, got %v", got)
	}
}

func TestCloudBackoffMetaFailureRetriesMetaOnly(t *testing.T) {
	// meta_failed on attempt 1 -> attempt 2 posts ONLY the meta step; the
	// binary is already stored under sha1.
	s, b := newCloudBackend(t)
	var metaN int32
	s.metaFn = func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&metaN, 1) == 1 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitWithBackoff(f, ticloudSHA256, ticloudSHA1, nil,
		testArgs(), nil)
	if o.Kind != "receipt" || o.Ref != ticloudSHA1 {
		t.Fatalf("bad outcome: %+v", o)
	}
	want := []string{"upload", "meta", "meta"}
	if got := *s.order; len(got) != len(want) {
		t.Fatalf("bad order: %v", got)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("bad order: %v", got)
			}
		}
	}
	if *s.uploadCalls != 1 || *s.metaCalls != 2 {
		t.Fatalf("want 1 upload + 2 meta, got %d + %d",
			*s.uploadCalls, *s.metaCalls)
	}
}

func TestCloudBackoffBinaryFailureReuploads(t *testing.T) {
	// A binary-upload failure is NOT meta_failed — the retry reposts the
	// file body.
	s, b := newCloudBackend(t)
	var upN int32
	s.uploadFn = func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&upN, 1) == 1 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitWithBackoff(f, ticloudSHA256, ticloudSHA1, nil,
		testArgs(), nil)
	if o.Kind != "receipt" {
		t.Fatalf("bad outcome: %+v", o)
	}
	want := []string{"upload", "upload", "meta"}
	if got := *s.order; len(got) != len(want) {
		t.Fatalf("bad order: %v", got)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("bad order: %v", got)
			}
		}
	}
}

func TestCloudPermanent413NoRetry(t *testing.T) {
	s, b := newCloudBackend(t)
	s.uploadCode = 413
	s.uploadResp = "too big"
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitWithBackoff(f, ticloudSHA256, ticloudSHA1, nil,
		testArgs(), nil)
	if o.Kind != "error" || *o.HTTPStatus != 413 {
		t.Fatalf("bad outcome: %+v", o)
	}
	if *s.uploadCalls != 1 {
		t.Fatalf("413 permanent must not retry: %d calls", *s.uploadCalls)
	}
}

func TestCloudAuthErrorNeverRetried(t *testing.T) {
	for _, code := range []int{401, 403} {
		s, b := newCloudBackend(t)
		s.uploadCode = code
		s.uploadResp = "denied"
		f := writeFile(t, "a.bin", "x")
		o := b.SubmitWithBackoff(f, ticloudSHA256, ticloudSHA1, nil,
			testArgs(), nil)
		if o.Kind != "error" || *o.HTTPStatus != code {
			t.Fatalf("%d: bad outcome %+v", code, o)
		}
		if *s.uploadCalls != 1 {
			t.Fatalf("%d auth error must not retry: %d calls",
				code, *s.uploadCalls)
		}
	}
}

func TestCloudRetriableMarksUnavailable(t *testing.T) {
	for _, code := range []int{429, 500, 503} {
		s, b := newCloudBackend(t)
		s.uploadCode = code
		s.uploadResp = "busy"
		f := writeFile(t, "a.bin", "x")
		// one attempt, zero retry window — the loop breaks before
		// WaitReady can re-probe and flip the cache back.
		b.SubmitWithBackoff(f, ticloudSHA256, ticloudSHA1, nil,
			&Args{BackoffBase: 0, BackoffMax: 0, UploadRetryWindow: 0,
				MaxUploadAttempts: 1, ReadyCheckInterval: 0,
				ReadyMaxWait: 0, AvailProbeSeconds: 60}, nil)
		before := atomic.LoadInt32(s.probeCalls)
		if b.client.AvailableNow(60 * time.Second) {
			t.Fatalf("%d: cache should be False after retriable error",
				code)
		}
		if atomic.LoadInt32(s.probeCalls) != before {
			t.Fatal("AvailableNow must not re-probe inside TTL")
		}
	}
}

func TestCloudBackoffConnErrorRetried(t *testing.T) {
	s, b := newCloudBackend(t)
	var upN int32
	s.uploadFn = func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&upN, 1) == 1 {
			w.WriteHeader(408) // retriable per the ticloud taxonomy
			return
		}
		w.WriteHeader(200)
	}
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitWithBackoff(f, ticloudSHA256, ticloudSHA1, nil,
		testArgs(), nil)
	if o.Kind != "receipt" || o.Ref != ticloudSHA1 {
		t.Fatalf("bad outcome: %+v", o)
	}
	if atomic.LoadInt32(&upN) != 2 {
		t.Fatalf("want 2 upload attempts, got %d", upN)
	}
}

// -- poll ---------------------------------------------------------------------

func TestCloudPollBatchVerdictMapping(t *testing.T) {
	s, b := newCloudBackend(t)
	sha1c := strings.Repeat("c", 40)
	sha1d := strings.Repeat("d", 40)
	sha1e := strings.Repeat("e", 40)
	statusBy := map[string]string{
		ticloudSHA1: `"status":"MALICIOUS","threat_name":` +
			`"Win32.Backdoor.Poison","threat_level":9,"trust_factor":0`,
		sha1c: `"status":"SUSPICIOUS","threat_name":"Susp","threat_level":5`,
		sha1d: `"status":"KNOWN","trust_factor":4`,
		sha1e: `"status":"UNKNOWN"`,
	}
	s.bulkFn = func(hashes []string) string {
		var sb strings.Builder
		sb.WriteString(`{"rl":{"entries":[`)
		for i, h := range hashes {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"sha1":%q,%s}`, h, statusBy[h])
		}
		sb.WriteString(`],"invalid_hashes":[]}}`)
		return sb.String()
	}
	out := b.PollBatch([]PollRef{
		{Ref: ticloudSHA1}, {Ref: sha1c}, {Ref: sha1d}, {Ref: sha1e},
	})
	v, ok := out[ticloudSHA1].(map[string]any)
	if !ok || v["classification"] != "malicious" ||
		v["threat_name"] != "Win32.Backdoor.Poison" {
		t.Fatalf("bad verdict: %v", out[ticloudSHA1])
	}
	if f, _ := v["threat_factor"].(*int64); f == nil || *f != 9 {
		t.Fatalf("malicious factor should be threat_level 9: %+v",
			v["threat_factor"])
	}
	if v["report_json"] == nil {
		t.Fatal("report_json should carry the raw entry")
	}
	v, _ = out[sha1c].(map[string]any)
	if v["classification"] != "suspicious" {
		t.Fatalf("bad verdict: %v", v)
	}
	if f, _ := v["threat_factor"].(*int64); f == nil || *f != 5 {
		t.Fatalf("suspicious factor 5: %+v", v["threat_factor"])
	}
	v, _ = out[sha1d].(map[string]any)
	if v["classification"] != "goodware" {
		t.Fatalf("bad verdict: %v", v)
	}
	if f, _ := v["threat_factor"].(*int64); f == nil || *f != 4 {
		t.Fatalf("KNOWN factor should be trust_factor 4: %+v",
			v["threat_factor"])
	}
	if out[sha1e] != "pending" {
		t.Fatalf("UNKNOWN should stay pending: %v", out[sha1e])
	}
	// queried with hash_type=sha1 over the receipt hashes
	if q := *s.bulkQuery; q["hash_type"] != "sha1" {
		t.Fatalf("bulk should query sha1: %v", q)
	}
	if *s.bulkCalls != 1 {
		t.Fatalf("want 1 bulk call, got %d", *s.bulkCalls)
	}
}

func TestCloudPollBatchPendingStates(t *testing.T) {
	s, b := newCloudBackend(t)
	// entry absent for the queried sha1 -> pending
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[{"sha256":"` + ticloudSHA256 +
			`","status":"MALICIOUS","threat_level":9}],"invalid_hashes":[]}}`
	}
	out := b.PollBatch([]PollRef{
		{Ref: ticloudSHA1}, {Ref: "not-a-sha1"}, {Ref: ""},
	})
	if out[ticloudSHA1] != "pending" || out["not-a-sha1"] != "pending" {
		t.Fatalf("want pending,pending: %v", out)
	}
	if *s.bulkCalls != 1 {
		t.Fatal("pollable sha1 should still hit the bulk endpoint")
	}
}

func TestCloudPollBatchBulkFailureAllPending(t *testing.T) {
	s, b := newCloudBackend(t)
	s.srv.Close() // conn failure on the bulk endpoint
	out := b.PollBatch([]PollRef{{Ref: ticloudSHA1},
		{Ref: strings.Repeat("c", 40)}})
	if out[ticloudSHA1] != "pending" ||
		out[strings.Repeat("c", 40)] != "pending" {
		t.Fatalf("bulk failure should map all refs to pending: %v", out)
	}
}

func TestCloudPollBatchEntryByOtherHashFields(t *testing.T) {
	s, b := newCloudBackend(t)
	sha1c := strings.Repeat("c", 40)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[` +
			`{"sha256":"` + ticloudSHA256 + `","sha1":"` + ticloudSHA1 +
			`","status":"KNOWN","trust_factor":7},` +
			`{"hash_value":"` + sha1c +
			`","status":"MALICIOUS","threat_level":2}],"invalid_hashes":[]}}`
	}
	out := b.PollBatch([]PollRef{{Ref: ticloudSHA1}, {Ref: sha1c}})
	if v, _ := out[ticloudSHA1].(map[string]any); v == nil ||
		v["classification"] != "goodware" {
		t.Fatalf("bad outcome: %v", out[ticloudSHA1])
	}
	if v, _ := out[sha1c].(map[string]any); v == nil ||
		v["classification"] != "malicious" {
		t.Fatalf("bad outcome: %v", out[sha1c])
	}
}

func TestCloudPollBatchRealQueryHashShape(t *testing.T) {
	// Regression: the real TCA-0101 response nests the echoed hash under
	// query_hash.{sha1,md5,sha256} — NOT flat fields (verified live against
	// ticloud01, EICAR entry). Mock shape missed this; every ref would poll
	// 'pending' forever.
	s, b := newCloudBackend(t)
	s.bulkFn = func(hashes []string) string {
		return `{"rl":{"entries":[{` +
			`"status":"MALICIOUS",` +
			`"query_hash":{"sha1":"` + ticloudSHA1 + `"},` +
			`"first_seen":"2011-05-29T19:39:00",` +
			`"reason":"analyst_sample_override",` +
			`"trust_factor":5,"threat_level":2,` +
			`"scanner_count":36,"scanner_match":34,` +
			`"threat_name":"DOS.Malware.EICAR",` +
			`"classification":{"platform":"DOS","family_name":"EICAR",` +
			`"type":"Malware"}}],"invalid_hashes":[]}}`
	}
	out := b.PollBatch([]PollRef{{Ref: ticloudSHA1}})
	v, _ := out[ticloudSHA1].(map[string]any)
	if v == nil || v["classification"] != "malicious" {
		t.Fatalf("query_hash entry should resolve: %v", out[ticloudSHA1])
	}
	if v["threat_name"] != "DOS.Malware.EICAR" {
		t.Fatalf("bad threat_name: %v", v)
	}
}

func TestCloudPollBatchNothingPollableNoCall(t *testing.T) {
	s, b := newCloudBackend(t)
	out := b.PollBatch([]PollRef{{}, {Ref: "nope"}})
	if out["nope"] != "pending" {
		t.Fatalf("unhashable ref should stay pending: %v", out)
	}
	if *s.bulkCalls != 0 {
		t.Fatal("nothing pollable must not hit the bulk endpoint")
	}
}

// -- factory ------------------------------------------------------------------

func TestMakeBackendCloud(t *testing.T) {
	s, _ := newTicloudTestServer(t)
	b, err := makeBackend(&Args{Backend: "cloud", TicloudHost: s.srv.URL,
		TicloudUsername: ticloudUser, TicloudPassword: ticloudPass,
		TicloudDomain: "corp.local", TicloudArchivePassword: "pw",
		TicloudUploadTimeout: 10, TicloudMinIntervalMs: 0,
		TicloudExtended: true})
	if err != nil || b == nil || b.Name() != "cloud" {
		t.Fatalf("cloud: %v %+v", err, b)
	}
	cb, ok := b.(*CloudBackend)
	if !ok || cb.client.Host != s.srv.URL {
		t.Fatalf("bad cloud backend: %+v", b)
	}
	if cb.domain != "corp.local" || cb.archivePassword != "pw" {
		t.Fatalf("bad config passthrough: %+v", cb)
	}
	if !cb.NeedsSHA1() || cb.IsSync() {
		t.Fatal("cloud must be needs_sha1 async")
	}
	if *s.probeCalls == 0 || *s.lastAuth != basicAuthWant() {
		t.Fatal("factory must probe once with Basic auth")
	}
	for _, a := range []*Args{
		{Backend: "cloud"},                         // no host
		{Backend: "cloud", TicloudHost: s.srv.URL}, // no creds
		{Backend: "cloud", TicloudHost: s.srv.URL,
			TicloudUsername: "u"}, // no password
		{Backend: "cloud", TicloudHost: s.srv.URL,
			TicloudPassword: "p"}, // no username
	} {
		if _, err := makeBackend(a); err == nil {
			t.Fatalf("%+v should error (missing config)", a)
		}
	}
}

func TestMakeBackendCloudAuthFailFast(t *testing.T) {
	for _, code := range []int{401, 403} {
		s, _ := newTicloudTestServer(t)
		s.probeCode = code
		_, err := makeBackend(&Args{Backend: "cloud",
			TicloudHost: s.srv.URL, TicloudUsername: "u",
			TicloudPassword: "p"})
		if err == nil || !strings.Contains(err.Error(), "ticloud") {
			t.Fatalf("%d should fail fast with a clear message: %v",
				code, err)
		}
	}
}

func TestMakeBackendCloudUnreachableNotFatal(t *testing.T) {
	// conn error / 5xx at the startup probe are NOT auth failures — the
	// backend still constructs and WaitReady is the reachability gate.
	s, _ := newTicloudTestServer(t)
	s.probeCode = 503
	if _, err := makeBackend(&Args{Backend: "cloud",
		TicloudHost: s.srv.URL, TicloudUsername: "u",
		TicloudPassword: "p"}); err != nil {
		t.Fatalf("5xx probe should not fail construction: %v", err)
	}
	s.srv.Close()
	if _, err := makeBackend(&Args{Backend: "cloud",
		TicloudHost: s.srv.URL, TicloudUsername: "u",
		TicloudPassword: "p"}); err != nil {
		t.Fatalf("unreachable host should not fail construction: %v", err)
	}
}
