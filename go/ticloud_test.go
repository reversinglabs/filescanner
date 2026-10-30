// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	ticloudSHA1   = strings.Repeat("b", 40)
	ticloudSHA256 = strings.Repeat("a", 64)
)

const (
	ticloudUser = "user@example.com"
	ticloudPass = "pw-secret"
)

// ticloudTestServer mimics the TitaniumCloud endpoints: GET / (probe),
// POST /api/spex/upload/{sha1} (binary), POST /api/spex/upload/{sha1}/meta
// (XML), POST /api/databrowser/malware_presence/bulk_query/json and
// GET /api/databrowser/malware_presence/query/{hash_type}/{h} (TCA-0101).
type ticloudTestServer struct {
	srv *httptest.Server

	uploadCalls, metaCalls, bulkCalls, singleCalls, probeCalls *int32
	redirectHits                                               *int32
	lastAuth                                                   *string
	uploadBody                                                 *[]byte
	metaBody                                                   *[]byte
	order                                                      *[]string
	bulkSizes                                                  *[]int
	bulkQuery                                                  *map[string]any
	bulkExtended                                               *string

	probeCode  int
	uploadCode int
	uploadResp string
	uploadFn   http.HandlerFunc // overrides uploadCode/uploadResp
	metaCode   int
	metaResp   string
	metaFn     http.HandlerFunc // overrides metaCode/metaResp
	bulkFn     func(hashes []string) string
	singleCode int
	singleBody string
}

func newTicloudTestServer(t *testing.T) (*ticloudTestServer, *TicloudClient) {
	t.Helper()
	s := &ticloudTestServer{
		probeCode: 200, uploadCode: 200, metaCode: 200, singleCode: 200,
		uploadCalls: new(int32), metaCalls: new(int32),
		bulkCalls: new(int32), singleCalls: new(int32),
		probeCalls: new(int32), redirectHits: new(int32),
		lastAuth: new(string), uploadBody: new([]byte),
		metaBody: new([]byte), order: new([]string),
		bulkSizes: new([]int), bulkQuery: new(map[string]any),
		bulkExtended: new(string),
	}
	s.bulkFn = func(hashes []string) string {
		var b strings.Builder
		b.WriteString(`{"rl":{"entries":[`)
		for i, h := range hashes {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"sha256":%q,"status":"UNKNOWN"}`, h)
		}
		b.WriteString(`],"invalid_hashes":[]}}`)
		return b.String()
	}
	s.singleBody = `{"rl":{"entries":[{"sha256":"` + ticloudSHA256 +
		`","status":"MALICIOUS","threat_name":"Win32.Backdoor.Poison",` +
		`"threat_level":9,"trust_factor":0,"scanner_count":41}]}}`
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		*s.lastAuth = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/redirected":
			atomic.AddInt32(s.redirectHits, 1)
			w.WriteHeader(200)
		case r.Method == "GET" && r.URL.Path == "/":
			atomic.AddInt32(s.probeCalls, 1)
			if s.probeCode >= 300 && s.probeCode < 400 {
				// a redirect target that must never be hit — following it
				// would carry the Basic credentials cross-origin.
				w.Header().Set("Location", "/redirected")
			}
			w.WriteHeader(s.probeCode)
		case r.Method == "POST" &&
			strings.HasPrefix(r.URL.Path, "/api/spex/upload/") &&
			strings.HasSuffix(r.URL.Path, "/meta"):
			atomic.AddInt32(s.metaCalls, 1)
			*s.order = append(*s.order, "meta")
			b, _ := io.ReadAll(r.Body)
			*s.metaBody = b
			if ct := r.Header.Get("Content-Type"); ct !=
				"application/octet-stream" {
				t.Errorf("meta Content-Type: %q", ct)
			}
			if s.metaFn != nil {
				s.metaFn(w, r)
				return
			}
			w.WriteHeader(s.metaCode)
			fmt.Fprint(w, s.metaResp)
		case r.Method == "POST" &&
			strings.HasPrefix(r.URL.Path, "/api/spex/upload/"):
			atomic.AddInt32(s.uploadCalls, 1)
			*s.order = append(*s.order, "upload")
			sha := strings.TrimPrefix(r.URL.Path, "/api/spex/upload/")
			if sha != strings.ToLower(sha) || !isA1000SHA1(sha) {
				t.Errorf("upload sha1 path param not lowercase 40-hex: %q",
					sha)
			}
			b, _ := io.ReadAll(r.Body)
			*s.uploadBody = b
			if ct := r.Header.Get("Content-Type"); ct !=
				"application/octet-stream" {
				t.Errorf("upload Content-Type: %q", ct)
			}
			if r.Header.Get("Content-Length") == "" {
				t.Error("upload POST missing Content-Length")
			}
			if s.uploadFn != nil {
				s.uploadFn(w, r)
				return
			}
			w.WriteHeader(s.uploadCode)
			fmt.Fprint(w, s.uploadResp)
		case r.Method == "POST" && r.URL.Path ==
			"/api/databrowser/malware_presence/bulk_query/json":
			*s.bulkExtended = r.URL.Query().Get("extended")
			var req struct {
				Rl struct {
					Query struct {
						HashType string   `json:"hash_type"`
						Hashes   []string `json:"hashes"`
					} `json:"query"`
				} `json:"rl"`
			}
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &req); err != nil {
				t.Errorf("bulk body not json: %v", err)
			}
			*s.bulkQuery = map[string]any{"hash_type": req.Rl.Query.HashType}
			*s.bulkSizes = append(*s.bulkSizes, len(req.Rl.Query.Hashes))
			// publish after the writes so readers synchronised on bulkCalls see them
			atomic.AddInt32(s.bulkCalls, 1)
			w.WriteHeader(200)
			fmt.Fprint(w, s.bulkFn(req.Rl.Query.Hashes))
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path,
			"/api/databrowser/malware_presence/query/"):
			atomic.AddInt32(s.singleCalls, 1)
			w.WriteHeader(s.singleCode)
			fmt.Fprint(w, s.singleBody)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s, NewTicloudClient(s.srv.URL, ticloudUser, ticloudPass, true, "",
		300*time.Second, 0, true)
}

func basicAuthWant() string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(ticloudUser+":"+ticloudPass))
}

// -- probe / auth ---------------------------------------------------------------

func TestTicloudProbeAndBasicAuth(t *testing.T) {
	s, c := newTicloudTestServer(t)
	for _, code := range []int{200, 302, 401, 403, 404} {
		s.probeCode = code
		if !c.probe(2 * time.Second) {
			t.Fatalf("probe %d should be up (any <500 answer)", code)
		}
	}
	s.probeCode = 503
	if c.probe(2 * time.Second) {
		t.Fatal("probe 503 should be down")
	}
	if *s.probeCalls == 0 {
		t.Fatal("probe never reached GET /")
	}
	if *s.lastAuth != basicAuthWant() {
		t.Fatalf("Basic auth header wrong: %q", *s.lastAuth)
	}
}

func TestTicloudProbeRedirectNotFollowed(t *testing.T) {
	s, c := newTicloudTestServer(t)
	// a 302 is "answered <500" = up, but the client must NOT follow it —
	// the Basic credentials would leak to the redirect target.
	s.probeCode = 302
	if !c.probe(2 * time.Second) {
		t.Fatal("302 answer should still count as up")
	}
	if *s.redirectHits != 0 {
		t.Fatal("redirect was followed — credential leak risk")
	}
}

func TestTicloudAvailableNowCachesAndMarks(t *testing.T) {
	s, c := newTicloudTestServer(t)
	if !c.AvailableNow(60 * time.Second) {
		t.Fatal("expected up")
	}
	c.MarkUnavailable()
	before := atomic.LoadInt32(s.probeCalls)
	if c.AvailableNow(60 * time.Second) {
		t.Fatal("cache should be False after MarkUnavailable")
	}
	if atomic.LoadInt32(s.probeCalls) != before {
		t.Fatal("AvailableNow must not re-probe inside TTL")
	}
}

// -- upload_sample / upload_meta -------------------------------------------------

func TestTicloudUploadSample(t *testing.T) {
	s, c := newTicloudTestServer(t)
	f := writeFile(t, "a.bin", "MZpayload")
	res := c.UploadSample(ticloudSHA1, f)
	if res.err != "" || !res.ok || res.status != 200 {
		t.Fatalf("bad upload: %+v", res)
	}
	if string(*s.uploadBody) != "MZpayload" {
		t.Fatalf("body mismatch: %q", *s.uploadBody)
	}
	if *s.lastAuth != basicAuthWant() {
		t.Fatal("upload missing Basic auth header")
	}
}

func TestTicloudUploadSampleSHA1Validated(t *testing.T) {
	s, c := newTicloudTestServer(t)
	f := writeFile(t, "a.bin", "x")
	res := c.UploadSample("not-a-sha1", f)
	if res.err != "invalid sha1" {
		t.Fatalf("want invalid sha1, got %+v", res)
	}
	if *s.uploadCalls != 0 {
		t.Fatal("invalid sha1 must not hit the wire")
	}
	// uppercase sha1 is lowercased into the path
	res = c.UploadSample(strings.ToUpper(ticloudSHA1), f)
	if !res.ok {
		t.Fatalf("uppercase sha1 should pass after lowercasing: %+v", res)
	}
}

func TestTicloudMetaXMLShape(t *testing.T) {
	got := ticloudMetaXML("/tmp/dir/evil.exe", "corp.local", "")
	want := "<rl><properties><property><name>filename</name>" +
		"<value>evil.exe</value></property><property><name>source</name>" +
		"<value>filescanner</value></property></properties>" +
		"<domain>corp.local</domain></rl>"
	if got != want {
		t.Fatalf("meta xml mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestTicloudMetaXMLEscapingAndArchive(t *testing.T) {
	got := ticloudMetaXML(`a<b>&"c'.bin`, "<dom&>", "p<x")
	for _, raw := range []string{`a<b>&"c'.bin`, "<dom&>", "p<x"} {
		if strings.Contains(got, raw) {
			t.Fatalf("unescaped value %q in %s", raw, got)
		}
	}
	for _, esc := range []string{"a&lt;b&gt;&amp;&#34;c&#39;.bin",
		"&lt;dom&amp;&gt;", "p&lt;x"} {
		if !strings.Contains(got, esc) {
			t.Fatalf("missing %q in %s", esc, got)
		}
	}
	if !strings.Contains(got, "<archive><archive_passwords>"+
		"<password>p&lt;x</password></archive_passwords></archive>") {
		t.Fatalf("archive element missing: %s", got)
	}
	if strings.Contains(ticloudMetaXML("a.bin", "d", ""), "<archive>") {
		t.Fatal("archive element must be absent without a password")
	}
}

func TestTicloudTwoStepOrder(t *testing.T) {
	s, c := newTicloudTestServer(t)
	f := writeFile(t, "a.bin", "MZpayload")
	res := c.SubmitSample(ticloudSHA1, f, "", "corp.local", "", false)
	if res.err != "" || !res.ok {
		t.Fatalf("bad submit: %+v", res)
	}
	want := []string{"upload", "meta"}
	if fmt.Sprint(*s.order) != fmt.Sprint(want) {
		t.Fatalf("two-step order wrong: %v", *s.order)
	}
	if !strings.Contains(string(*s.metaBody), "<value>a.bin</value>") {
		t.Fatalf("meta filename should be the basename: %s", *s.metaBody)
	}
	if !strings.Contains(string(*s.metaBody),
		"<domain>corp.local</domain>") {
		t.Fatalf("meta domain missing: %s", *s.metaBody)
	}
}

func TestTicloudMetaOnlyRetry(t *testing.T) {
	// meta failure after a good binary upload -> "meta_failed:"; a retry
	// with sampleUploaded=true posts ONLY the meta step.
	s, c := newTicloudTestServer(t)
	s.metaCode = 500
	s.metaResp = "meta boom"
	f := writeFile(t, "a.bin", "x")
	res := c.SubmitSample(ticloudSHA1, f, "", "", "", false)
	if res.ok || !strings.HasPrefix(res.err, "meta_failed: http_500") {
		t.Fatalf("bad meta failure: %+v", res)
	}
	s.metaCode = 200
	res = c.SubmitSample(ticloudSHA1, f, "", "", "", true)
	if res.err != "" || !res.ok {
		t.Fatalf("meta-only retry failed: %+v", res)
	}
	want := []string{"upload", "meta", "meta"}
	if fmt.Sprint(*s.order) != fmt.Sprint(want) {
		t.Fatalf("binary must not be re-uploaded: %v", *s.order)
	}
}

func TestTicloudSpexPacing(t *testing.T) {
	s, c := newTicloudTestServer(t)
	c.minInterval = 60 * time.Millisecond
	f := writeFile(t, "a.bin", "x")
	t0 := time.Now()
	c.UploadSample(ticloudSHA1, f)
	c.UploadSample(ticloudSHA1, f)
	if el := time.Since(t0); el < 55*time.Millisecond {
		t.Fatalf("spex pacing not honored: %v for 2 calls", el)
	}
	if *s.uploadCalls != 2 {
		t.Fatalf("want 2 uploads, got %d", *s.uploadCalls)
	}
}

// -- reputation -----------------------------------------------------------------

func TestTicloudBulkChunkAndParse(t *testing.T) {
	s, c := newTicloudTestServer(t)
	hashes := make([]string, 250)
	for i := range hashes {
		hashes[i] = fmt.Sprintf("%064x", i)
	}
	s.bulkFn = func(hs []string) string {
		var b strings.Builder
		b.WriteString(`{"rl":{"entries":[`)
		for i, h := range hs {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"sha256":%q,"status":"UNKNOWN"}`, h)
		}
		b.WriteString(`],"invalid_hashes":[]}}`)
		return b.String()
	}
	st, entries, invalid, errStr := c.ReputationBulk(hashes, "sha256")
	if errStr != "" || st != 200 || len(entries) != 250 ||
		len(invalid) != 0 {
		t.Fatalf("bad bulk: st=%d n=%d inv=%d err=%q",
			st, len(entries), len(invalid), errStr)
	}
	want := []int{100, 100, 50}
	if fmt.Sprint(*s.bulkSizes) != fmt.Sprint(want) {
		t.Fatalf("chunk sizes wrong: %v", *s.bulkSizes)
	}
	if *s.bulkExtended != "true" {
		t.Fatalf("extended param wrong: %q", *s.bulkExtended)
	}
	if (*s.bulkQuery)["hash_type"] != "sha256" {
		t.Fatalf("hash_type wrong: %v", *s.bulkQuery)
	}
}

func TestTicloudBulkInvalidHashesAndExtendedFalse(t *testing.T) {
	s, c := newTicloudTestServer(t)
	c.extended = false
	s.bulkFn = func(hs []string) string {
		return `{"rl":{"entries":[],"invalid_hashes":[` +
			`{"hash_value":"bad","reason":"invalid"}]}}`
	}
	st, entries, invalid, errStr := c.ReputationBulk(
		[]string{ticloudSHA256}, "sha1")
	if errStr != "" || st != 200 {
		t.Fatalf("bad bulk: %d %q", st, errStr)
	}
	if len(entries) != 0 || len(invalid) != 1 {
		t.Fatalf("entries/invalid wrong: %v %v", entries, invalid)
	}
	if *s.bulkExtended != "false" {
		t.Fatalf("extended=false not sent: %q", *s.bulkExtended)
	}
	if (*s.bulkQuery)["hash_type"] != "sha1" {
		t.Fatalf("hash_type wrong: %v", *s.bulkQuery)
	}
}

func TestTicloudBulkErrors(t *testing.T) {
	s, c := newTicloudTestServer(t)
	// invalid hash_type never hits the wire
	if _, _, _, e := c.ReputationBulk([]string{ticloudSHA256}, "sha512"); !strings.Contains(e, "invalid hash_type") {
		t.Fatalf("want invalid hash_type, got %q", e)
	}
	if *s.bulkCalls != 0 {
		t.Fatal("invalid hash_type must not hit the wire")
	}
	// malformed bodies
	s.bulkFn = func(hs []string) string { return `{"unexpected":1}` }
	if _, _, _, e := c.ReputationBulk([]string{ticloudSHA256}, "sha256"); e != "invalid reputation response body" {
		t.Fatalf("want invalid body, got %q", e)
	}
	// conn error
	s.srv.Close()
	if st, _, _, e := c.ReputationBulk([]string{ticloudSHA256}, "sha256"); st != 0 || !strings.HasPrefix(e, "request_error:") {
		t.Fatalf("conn error: st=%d err=%q", st, e)
	}
}

func TestTicloudSingleQuery(t *testing.T) {
	s, c := newTicloudTestServer(t)
	st, ent, errStr := c.ReputationSingle(ticloudSHA256, "sha256")
	if errStr != "" || st != 200 {
		t.Fatalf("bad single: %d %q", st, errStr)
	}
	if ent["status"] != "MALICIOUS" ||
		ent["threat_name"] != "Win32.Backdoor.Poison" {
		t.Fatalf("bad entry: %v", ent)
	}
	// rl.entry dict form also accepted
	s.singleBody = `{"rl":{"entry":{"status":"KNOWN","trust_factor":4}}}`
	_, ent, errStr = c.ReputationSingle(ticloudSHA256, "sha256")
	if errStr != "" || ent["status"] != "KNOWN" {
		t.Fatalf("entry dict form: %v %q", ent, errStr)
	}
	// validation keeps junk off the wire
	if _, _, e := c.ReputationSingle("zz", "sha256"); e != "invalid hash" {
		t.Fatalf("want invalid hash, got %q", e)
	}
	if _, _, e := c.ReputationSingle(ticloudSHA256, "crc32"); !strings.Contains(e, "invalid hash_type") {
		t.Fatalf("want invalid hash_type, got %q", e)
	}
	s.singleCode = 404
	s.singleBody = "gone"
	if st, _, e := c.ReputationSingle(ticloudSHA256, "sha256"); st != 404 || !strings.HasPrefix(e, "http_404") {
		t.Fatalf("404: st=%d err=%q", st, e)
	}
}

// -- normalization / taxonomy / credentials ----------------------------------------

func TestTicloudNormalizeReputationEntry(t *testing.T) {
	f9, f5, f4, f3 := int64(9), int64(5), int64(4), int64(3)
	cases := []struct {
		entry      map[string]any
		wantCls    string
		wantFactor *int64
	}{
		{map[string]any{"status": "MALICIOUS", "threat_name": "T",
			"threat_level": float64(9), "trust_factor": float64(0)},
			"malicious", &f9},
		{map[string]any{"status": "SUSPICIOUS", "threat_level": float64(5)},
			"suspicious", &f5},
		{map[string]any{"status": "KNOWN", "trust_factor": float64(4)},
			"goodware", &f4},
		{map[string]any{"status": "UNKNOWN"}, "unknown", nil},
		{map[string]any{"status": "weird"}, "unknown", nil},
		{map[string]any{"status": "malicious", "threat_level": float64(3)},
			"malicious", &f3},
		{nil, "unknown", nil},
	}
	for i, tc := range cases {
		v := normalizeReputationEntry(tc.entry)
		if v["classification"] != tc.wantCls {
			t.Fatalf("%d: cls %v", i, v["classification"])
		}
		f, _ := v["threat_factor"].(*int64)
		if tc.wantFactor == nil {
			if f != nil {
				t.Fatalf("%d: factor should be nil: %v", i, *f)
			}
		} else if f == nil || *f != *tc.wantFactor {
			t.Fatalf("%d: factor %v want %v", i, f, *tc.wantFactor)
		}
		if v["raw"] == nil {
			t.Fatalf("%d: raw missing", i)
		}
	}
	// threat_name surfaced; junk factor types -> nil *int64 (typed nil
	// pointer inside the interface — same convention as a1000VerdictMap)
	v := normalizeReputationEntry(map[string]any{
		"status": "MALICIOUS", "threat_name": "T", "threat_level": "high"})
	f, _ := v["threat_factor"].(*int64)
	if v["threat_name"] != "T" || f != nil {
		t.Fatalf("bad fields: %v", v)
	}
}

func TestTicloudErrorTaxonomyConstants(t *testing.T) {
	if !ticloudAuthStatuses[401] || !ticloudAuthStatuses[403] {
		t.Fatal("401/403 must be auth statuses")
	}
	if !ticloudPermanentStatuses[413] {
		t.Fatal("413 must be permanent")
	}
	if !ticloudRetriableStatuses[408] || !ticloudRetriableStatuses[429] {
		t.Fatal("408/429 must be retriable")
	}
}

func TestTicloudAuthStatusSurfaced(t *testing.T) {
	// 401/403 carry their status so the factory can fail fast.
	for _, code := range []int{401, 403} {
		s, c := newTicloudTestServer(t)
		s.uploadCode = code
		s.uploadResp = "denied"
		f := writeFile(t, "a.bin", "x")
		res := c.UploadSample(ticloudSHA1, f)
		if res.ok || !ticloudAuthStatuses[res.status] {
			t.Fatalf("%d should surface as auth status: %+v", code, res)
		}
	}
}

func TestTicloudCredentialsNeverInErrors(t *testing.T) {
	s, c := newTicloudTestServer(t)
	s.uploadCode = 500
	s.uploadResp = "failure details: " + ticloudUser + ":" +
		ticloudPass + " echoed"
	f := writeFile(t, "a.bin", "x")
	res := c.UploadSample(ticloudSHA1, f)
	if strings.Contains(res.err, ticloudPass) ||
		strings.Contains(res.err, ticloudUser) {
		t.Fatalf("credentials leaked into error: %q", res.err)
	}
	if !strings.Contains(res.err, "***") {
		t.Fatalf("credentials not redacted: %q", res.err)
	}
}
