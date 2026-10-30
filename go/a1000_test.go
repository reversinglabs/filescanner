// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	a1000SHA1   = strings.Repeat("b", 40)
	a1000SHA256 = strings.Repeat("a", 64)
)

// a1000TestServer mimics the A1000 endpoints: GET /api/uploads/ (probe),
// POST /api/uploads/ (submit), POST /api/samples/status/ (bulk status),
// GET /api/samples/v3/{h}/classification/, POST /api/samples/v2/list/details/.
type a1000TestServer struct {
	srv *httptest.Server

	uploadCalls, statusCalls, clsCalls, detailsCalls, probeCalls *int32
	uploadFields                                                 map[string]string
	uploadFile                                                   []byte
	uploadFilename                                               string
	lastAuth                                                     *string

	probeCode    int
	uploadCode   int
	uploadBody   string
	uploadFn     http.HandlerFunc // overrides uploadCode/uploadBody
	statusFn     func(hashes []string) map[string]string
	clsCode      int
	clsBody      string
	detailsCode  int
	detailsFn    func(hashes []string) string
	redirectHits *int32
}

func newA1000TestServer(t *testing.T) (*a1000TestServer, *A1000Backend) {
	t.Helper()
	s := &a1000TestServer{
		probeCode: 200, uploadCode: 201,
		uploadBody: `{"detail":{"sha1":"` + a1000SHA1 + `"}}`,
		clsCode:    200,
		clsBody: `{"classification":"MALICIOUS","classification_result":` +
			`"Win32.Backdoor.Poison","riskscore":9}`,
		detailsCode: 200,
		uploadCalls: new(int32), statusCalls: new(int32),
		clsCalls: new(int32), detailsCalls: new(int32),
		probeCalls: new(int32), redirectHits: new(int32),
		lastAuth:     new(string),
		uploadFields: map[string]string{},
	}
	s.statusFn = func(hashes []string) map[string]string {
		m := map[string]string{}
		for _, h := range hashes {
			m[h] = "processed"
		}
		return m
	}
	s.detailsFn = func(hashes []string) string {
		return `{"count":1,"results":[{"sha256":"` + hashes[0] +
			`","classification":"MALICIOUS","classification_result":` +
			`"Win32.Backdoor.Poison","riskscore":9}]}`
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		*s.lastAuth = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/redirected":
			atomic.AddInt32(s.redirectHits, 1)
			w.WriteHeader(200)
		case r.Method == "GET" && r.URL.Path == "/api/uploads/":
			atomic.AddInt32(s.probeCalls, 1)
			if s.probeCode >= 300 && s.probeCode < 400 {
				// a redirect target that must never be hit — following it
				// would carry the Authorization token cross-origin.
				w.Header().Set("Location", "/redirected")
			}
			w.WriteHeader(s.probeCode)
		case r.Method == "POST" && r.URL.Path == "/api/uploads/":
			atomic.AddInt32(s.uploadCalls, 1)
			mt, params, err := mime.ParseMediaType(
				r.Header.Get("Content-Type"))
			if err != nil || !strings.HasPrefix(mt, "multipart/") {
				t.Errorf("upload Content-Type not multipart: %q",
					r.Header.Get("Content-Type"))
			} else {
				mr := multipart.NewReader(r.Body, params["boundary"])
				for {
					p, err := mr.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Errorf("multipart parse: %v", err)
						break
					}
					buf, _ := io.ReadAll(p)
					if p.FormName() == "file" {
						s.uploadFile = buf
						s.uploadFilename = p.FileName()
					} else {
						s.uploadFields[p.FormName()] = string(buf)
					}
				}
			}
			if s.uploadFn != nil {
				s.uploadFn(w, r)
				return
			}
			w.WriteHeader(s.uploadCode)
			fmt.Fprint(w, s.uploadBody)
		case r.Method == "POST" && r.URL.Path == "/api/samples/status/":
			atomic.AddInt32(s.statusCalls, 1)
			var req struct {
				HashValues []string `json:"hash_values"`
			}
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &req); err != nil {
				t.Errorf("status body not json: %v", err)
			}
			res := s.statusFn(req.HashValues)
			w.WriteHeader(200)
			fmt.Fprint(w, `{"hash_type":"sha256","results":[`)
			first := true
			for h, st := range res {
				if !first {
					fmt.Fprint(w, ",")
				}
				first = false
				fmt.Fprintf(w, `{"hash_value":%q,"status":%q}`, h, st)
			}
			fmt.Fprint(w, `]}`)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path,
			"/api/samples/v3/") &&
			strings.HasSuffix(r.URL.Path, "/classification/"):
			atomic.AddInt32(s.clsCalls, 1)
			w.WriteHeader(s.clsCode)
			fmt.Fprint(w, s.clsBody)
		case r.Method == "POST" &&
			r.URL.Path == "/api/samples/v2/list/details/":
			atomic.AddInt32(s.detailsCalls, 1)
			var req struct {
				HashValues []string `json:"hash_values"`
				Fields     []string `json:"fields"`
			}
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &req)
			w.WriteHeader(s.detailsCode)
			fmt.Fprint(w, s.detailsFn(req.HashValues))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s, NewA1000Backend(NewA1000Client(s.srv.URL, "tok-secret", true, ""),
		map[string]string{}, "summary")
}

func TestA1000BackendInterface(t *testing.T) {
	var _ ScanBackend = (*A1000Backend)(nil)
}

func TestA1000BackendAttrsAndProbe(t *testing.T) {
	s, b := newA1000TestServer(t)
	if b.Name() != "a1000" || b.NeedsSHA1() || b.IsSync() {
		t.Fatalf("bad attrs: %s %v %v", b.Name(), b.NeedsSHA1(), b.IsSync())
	}
	for _, code := range []int{200, 401, 403, 405} {
		s.probeCode = code
		if !b.Probe(2 * time.Second) {
			t.Fatalf("probe %d should be up (any <500 answer)", code)
		}
	}
	s.probeCode = 503
	if b.Probe(2 * time.Second) {
		t.Fatal("probe 503 should be down")
	}
	if *s.probeCalls == 0 {
		t.Fatal("probe never reached /api/uploads/")
	}
	if *s.lastAuth != "Token tok-secret" {
		t.Fatalf("Authorization header wrong: %q", *s.lastAuth)
	}
}

func TestA1000ProbeRedirectNotFollowed(t *testing.T) {
	s, b := newA1000TestServer(t)
	// a 302 is "answered <500" = up, but the client must NOT follow it — the
	// Authorization token would leak to the redirect target.
	s.probeCode = 302
	if !b.Probe(2 * time.Second) {
		t.Fatal("302 answer should still count as up")
	}
	if *s.redirectHits != 0 {
		t.Fatal("redirect was followed — token leak risk")
	}
}

func TestA1000UploadReceiptAndFields(t *testing.T) {
	s, b := newA1000TestServer(t)
	b.fields = map[string]string{
		"analysis": "cloud", "tags": "usb,batch1", "comment": "hi",
		"archive_password":          "infected",
		"rl_cloud_sandbox_platform": "windows10"}
	f := writeFile(t, "a.bin", "MZpayload")
	o := b.SubmitOnce(f, a1000SHA256, "", nil)
	if o.Kind != "receipt" || o.Ref != a1000SHA1 {
		t.Fatalf("bad outcome: %+v", o)
	}
	if o.HTTPStatus == nil || *o.HTTPStatus != 201 {
		t.Fatalf("want http_status 201, got %+v", o.HTTPStatus)
	}
	want := map[string]string{
		"filename": "a.bin", "analysis": "cloud", "tags": "usb,batch1",
		"comment": "hi", "archive_password": "infected",
		"rl_cloud_sandbox_platform": "windows10"}
	for k, v := range want {
		if s.uploadFields[k] != v {
			t.Fatalf("field %q: want %q got %q", k, v, s.uploadFields[k])
		}
	}
	if s.uploadFilename != "a.bin" || string(s.uploadFile) != "MZpayload" {
		t.Fatalf("file part wrong: name=%q body=%q",
			s.uploadFilename, s.uploadFile)
	}
	if *s.lastAuth != "Token tok-secret" {
		t.Fatal("upload request missing Authorization: Token")
	}
}

func TestA1000UploadOmitsEmptyFields(t *testing.T) {
	s, b := newA1000TestServer(t)
	b.fields = map[string]string{"analysis": "local", "tags": "",
		"comment": "", "archive_password": "",
		"rl_cloud_sandbox_platform": ""}
	f := writeFile(t, "a.bin", "x")
	b.SubmitOnce(f, a1000SHA256, "", nil)
	if s.uploadFields["analysis"] != "local" {
		t.Fatalf("analysis field missing: %v", s.uploadFields)
	}
	for k := range s.uploadFields {
		if k != "analysis" && k != "filename" {
			t.Fatalf("unexpected field sent: %q", k)
		}
	}
}

func TestA1000UploadBadSHA1IsError(t *testing.T) {
	for _, body := range []string{
		`{"detail":{"sha1":"not-hex"}}`, `{"detail":{}}`,
		`{"detail":"nope"}`, `["not","dict"]`, `{}`} {
		s, b := newA1000TestServer(t)
		s.uploadBody = body
		f := writeFile(t, "a.bin", "x")
		o := b.SubmitOnce(f, a1000SHA256, "", nil)
		if o.Kind != "error" || o.HTTPStatus == nil || *o.HTTPStatus != 201 {
			t.Fatalf("%s: bad outcome %+v", body, o)
		}
	}
}

func TestA1000TokenNeverInErrors(t *testing.T) {
	s, b := newA1000TestServer(t)
	s.uploadCode = 500
	s.uploadBody = "failure details: Token tok-secret echoed"
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitOnce(f, a1000SHA256, "", nil)
	if o.Kind != "error" || o.Error == nil {
		t.Fatalf("bad outcome: %+v", o)
	}
	if strings.Contains(*o.Error, "tok-secret") {
		t.Fatalf("token leaked into error: %q", *o.Error)
	}
	if !strings.Contains(*o.Error, "***") {
		t.Fatalf("token not redacted: %q", *o.Error)
	}
}

func TestA1000StatusBulkChunking(t *testing.T) {
	s, _ := newA1000TestServer(t)
	var sizes []int
	s.statusFn = func(hashes []string) map[string]string {
		sizes = append(sizes, len(hashes))
		m := map[string]string{}
		for _, h := range hashes {
			m[h] = "processed"
		}
		return m
	}
	hashes := make([]string, 250)
	for i := range hashes {
		hashes[i] = fmt.Sprintf("%064x", i)
	}
	st, m, errStr := s.srvStatusBulk(t, hashes)
	if errStr != "" || st != 200 || len(m) != 250 {
		t.Fatalf("bad status_bulk: st=%d err=%q n=%d", st, errStr, len(m))
	}
	if len(sizes) != 3 || sizes[0] != 100 || sizes[1] != 100 ||
		sizes[2] != 50 {
		t.Fatalf("chunk sizes wrong: %v", sizes)
	}
}

// srvStatusBulk calls the client StatusBulk against the test server.
func (s *a1000TestServer) srvStatusBulk(t *testing.T,
	hashes []string) (int, map[string]string, string) {
	t.Helper()
	c := NewA1000Client(s.srv.URL, "tok-secret", true, "")
	return c.StatusBulk(hashes)
}

func TestA1000PollBatchSummaryVerdict(t *testing.T) {
	s, b := newA1000TestServer(t)
	out := b.PollBatch([]PollRef{{Ref: a1000SHA1, Sha256: a1000SHA256}})
	v, ok := out[a1000SHA1].(map[string]any)
	if !ok {
		t.Fatalf("want verdict map, got %v", out[a1000SHA1])
	}
	if v["classification"] != "malicious" ||
		v["threat_name"] != "Win32.Backdoor.Poison" {
		t.Fatalf("bad verdict: %+v", v)
	}
	if f, _ := v["threat_factor"].(*int64); f == nil || *f != 9 {
		t.Fatalf("bad threat_factor: %+v", v["threat_factor"])
	}
	if v["report_json"] == nil {
		t.Fatal("report_json must carry the raw classification doc")
	}
	if *s.statusCalls != 1 || *s.clsCalls != 1 || *s.detailsCalls != 0 {
		t.Fatalf("wrong calls: status=%d cls=%d details=%d",
			*s.statusCalls, *s.clsCalls, *s.detailsCalls)
	}
}

func TestA1000PollBatchVerdictMapping(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"MALICIOUS", "malicious"}, {"SUSPICIOUS", "suspicious"},
		{"GOODWARE", "goodware"}, {"UNKNOWN", "unknown"},
		{"weird", "unknown"},
	} {
		s, b := newA1000TestServer(t)
		s.clsBody = fmt.Sprintf(
			`{"classification":%q,"classification_result":"T","riskscore":7}`,
			tc.raw)
		out := b.PollBatch([]PollRef{{Ref: a1000SHA1, Sha256: a1000SHA256}})
		v := out[a1000SHA1].(map[string]any)
		if v["classification"] != tc.want || v["threat_name"] != "T" {
			t.Fatalf("%s: bad verdict %+v", tc.raw, v)
		}
	}
}

func TestA1000PollBatchFullReport(t *testing.T) {
	s, b := newA1000TestServer(t)
	b.reportDetail = "full"
	out := b.PollBatch([]PollRef{{Ref: a1000SHA1, Sha256: a1000SHA256}})
	v, ok := out[a1000SHA1].(map[string]any)
	if !ok || v["classification"] != "malicious" {
		t.Fatalf("bad outcome: %v", out[a1000SHA1])
	}
	entry, _ := v["report_json"].(map[string]any)
	if entry["sha256"] != a1000SHA256 {
		t.Fatalf("report_json should be the list/details entry: %v", entry)
	}
	if *s.detailsCalls != 1 || *s.clsCalls != 0 {
		t.Fatalf("full mode must hit list/details only: cls=%d details=%d",
			*s.clsCalls, *s.detailsCalls)
	}
}

func TestA1000PollBatchNotFoundAndMissingPending(t *testing.T) {
	s, b := newA1000TestServer(t)
	s.statusFn = func(hashes []string) map[string]string {
		// first hash not_found; second absent from results entirely
		return map[string]string{hashes[0]: "not_found"}
	}
	other := strings.Repeat("c", 64)
	out := b.PollBatch([]PollRef{
		{Ref: a1000SHA1, Sha256: a1000SHA256},
		{Ref: strings.Repeat("d", 40), Sha256: other},
	})
	if out[a1000SHA1] != "pending" ||
		out[strings.Repeat("d", 40)] != "pending" {
		t.Fatalf("want pending,pending: %v", out)
	}
	if *s.clsCalls != 0 {
		t.Fatal("not_found must not fetch a verdict")
	}
}

func TestA1000PollBatchRefIsHashFallback(t *testing.T) {
	// refs carry the row's sha256; absent that, the receipt itself (a sha1
	// hex) is a valid hash for the status API.
	s, b := newA1000TestServer(t)
	var got []string
	s.statusFn = func(hashes []string) map[string]string {
		got = hashes
		return map[string]string{hashes[0]: "processed"}
	}
	out := b.PollBatch([]PollRef{{Ref: a1000SHA1}})
	if v, _ := out[a1000SHA1].(map[string]any); v == nil ||
		v["classification"] != "malicious" {
		t.Fatalf("bad outcome: %v", out[a1000SHA1])
	}
	if len(got) != 1 || got[0] != a1000SHA1 {
		t.Fatalf("status poll should use the ref hash: %v", got)
	}
}

func TestA1000PollBatchBulkErrorAllPending(t *testing.T) {
	s, b := newA1000TestServer(t)
	// conn failure on the bulk endpoint -> every ref pending
	s.srv.Close()
	out := b.PollBatch([]PollRef{{Ref: a1000SHA1, Sha256: a1000SHA256}})
	if out[a1000SHA1] != "pending" {
		t.Fatalf("conn error should map to pending: %v", out)
	}
}

func TestA1000PollBatchVerdictFetchFailurePending(t *testing.T) {
	s, b := newA1000TestServer(t)
	s.clsCode = 500
	s.clsBody = "boom"
	out := b.PollBatch([]PollRef{{Ref: a1000SHA1, Sha256: a1000SHA256}})
	if out[a1000SHA1] != "pending" {
		t.Fatalf("fetch failure should be pending: %v", out)
	}
}

func TestA1000PollBatchSkipsUnhashable(t *testing.T) {
	_, b := newA1000TestServer(t)
	out := b.PollBatch([]PollRef{
		{}, {Ref: "not-a-hash"},
		{Ref: a1000SHA1, Sha256: a1000SHA256},
	})
	if out["not-a-hash"] != "pending" {
		t.Fatalf("unhashable ref should stay pending: %v", out)
	}
	if v, _ := out[a1000SHA1].(map[string]any); v == nil {
		t.Fatalf("processed ref should be a verdict: %v", out[a1000SHA1])
	}
}

func TestA1000PermanentNoRetry(t *testing.T) {
	for _, code := range []int{400, 413} {
		s, b := newA1000TestServer(t)
		s.uploadCode = code
		s.uploadBody = "bad request"
		f := writeFile(t, "a.bin", "x")
		o := b.SubmitWithBackoff(f, a1000SHA256, "", nil, testArgs(), nil)
		if o.Kind != "error" || *o.HTTPStatus != code {
			t.Fatalf("%d: bad outcome %+v", code, o)
		}
		if *s.uploadCalls != 1 {
			t.Fatalf("%d permanent must not retry: %d calls", code,
				*s.uploadCalls)
		}
	}
}

func TestA1000RetriableThenReceipt(t *testing.T) {
	s, b := newA1000TestServer(t)
	var n int32
	// first upload 429 (saturated), second succeeds
	s.uploadFn = func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(201)
		fmt.Fprint(w, `{"detail":{"sha1":"`+a1000SHA1+`"}}`)
	}
	f := writeFile(t, "a.bin", "x")
	o := b.SubmitWithBackoff(f, a1000SHA256, "", nil, testArgs(), nil)
	if o.Kind != "receipt" || o.Ref != a1000SHA1 {
		t.Fatalf("bad outcome: %+v", o)
	}
	if atomic.LoadInt32(&n) != 2 {
		t.Fatalf("want 2 upload attempts, got %d", n)
	}
}

func TestA1000ErrorMarksUnavailable(t *testing.T) {
	s, b := newA1000TestServer(t)
	s.uploadCode = 500
	s.uploadBody = "down"
	f := writeFile(t, "a.bin", "x")
	b.SubmitWithBackoff(f, a1000SHA256, "", nil,
		&Args{BackoffBase: 0, BackoffMax: 0, UploadRetryWindow: 0,
			MaxUploadAttempts: 1, ReadyCheckInterval: 0, ReadyMaxWait: 0,
			AvailProbeSeconds: 60}, nil)
	before := atomic.LoadInt32(s.probeCalls)
	if b.client.AvailableNow(60 * time.Second) {
		t.Fatal("cache should be False after 5xx")
	}
	if atomic.LoadInt32(s.probeCalls) != before {
		t.Fatal("AvailableNow must not re-probe inside TTL")
	}
}

func TestMakeBackendA1000(t *testing.T) {
	s, _ := newA1000TestServer(t)
	b, err := makeBackend(&Args{Backend: "a1000", A1000Host: s.srv.URL + "/",
		A1000Token: "tok-secret", A1000Analysis: "cloud",
		A1000Tags: "usb", A1000SandboxPlatform: "windows10",
		A1000ReportDetail: "full"})
	if err != nil || b == nil || b.Name() != "a1000" {
		t.Fatalf("a1000: %v %+v", err, b)
	}
	ab, ok := b.(*A1000Backend)
	if !ok || ab.client.Host != s.srv.URL {
		t.Fatalf("bad a1000 backend: %+v", b)
	}
	if ab.fields["analysis"] != "cloud" || ab.fields["tags"] != "usb" ||
		ab.fields["rl_cloud_sandbox_platform"] != "windows10" {
		t.Fatalf("bad fields: %v", ab.fields)
	}
	if ab.reportDetail != "full" {
		t.Fatalf("bad report_detail: %q", ab.reportDetail)
	}
	if _, err := makeBackend(&Args{Backend: "a1000"}); err == nil {
		t.Fatal("missing a1000.host should error")
	}
	if _, err := makeBackend(&Args{Backend: "a1000",
		A1000Host: s.srv.URL}); err == nil {
		t.Fatal("missing a1000.token should error")
	}
}

func TestMakeBackendA1000AuthFailFast(t *testing.T) {
	for _, code := range []int{401, 403} {
		s, _ := newA1000TestServer(t)
		s.probeCode = code
		_, err := makeBackend(&Args{Backend: "a1000", A1000Host: s.srv.URL,
			A1000Token: "bad-token"})
		if err == nil || !strings.Contains(err.Error(), "a1000") {
			t.Fatalf("%d should fail fast with a clear message: %v",
				code, err)
		}
	}
}

func TestMakeBackendA1000UnreachableNotFatal(t *testing.T) {
	// conn error / 5xx at the startup probe are NOT auth failures — the
	// backend still constructs and WaitReady is the reachability gate.
	s, _ := newA1000TestServer(t)
	s.probeCode = 503
	if _, err := makeBackend(&Args{Backend: "a1000",
		A1000Host: s.srv.URL, A1000Token: "t"}); err != nil {
		t.Fatalf("5xx probe should not fail construction: %v", err)
	}
	s.srv.Close()
	if _, err := makeBackend(&Args{Backend: "a1000",
		A1000Host: s.srv.URL, A1000Token: "t"}); err != nil {
		t.Fatalf("unreachable host should not fail construction: %v", err)
	}
}
