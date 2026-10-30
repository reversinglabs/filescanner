// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"=1+1": "'=1+1", "+x": "'+x", "-x": "'-x", "@x": "'@x",
		"\tx": "'\tx", "\rx": "'\rx", "plain": "plain", "": "",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q)=%q want %q", in, got, want)
		}
	}
}

func TestWriteCSVReportContent(t *testing.T) {
	tf := int64(42)
	out := map[string]any{"results": []map[string]any{{
		"file_path": "=cmd|' /c calc'!A1", "file_name": "a", "sha256": "ab",
		"classification": "malicious", "threat_factor": &tf,
		"cached": false, "quarantined_to": "/q/a", "alerted": true,
		"api": map[string]any{"status": "completed", "error": nil},
	}, {
		"file_path": "b", "classification": "goodware",
		"threat_factor": (*int64)(nil), "quarantined_to": nil, "alerted": nil,
		"api": map[string]any{"status": "completed"},
	}}}
	p := filepath.Join(t.TempDir(), "r.csv")
	if err := writeCSVReport(out, p, newLogger(false, "", 0, 0)); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(p)
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	col := map[string]int{}
	for i, c := range rows[0] {
		col[c] = i
	}
	r1, r2 := rows[1], rows[2]
	if !strings.HasPrefix(r1[col["file_path"]], "'=") {
		t.Errorf("formula not neutralised: %q", r1[col["file_path"]])
	}
	if r1[col["threat_factor"]] != "42" || r1[col["quarantined_to"]] != "/q/a" ||
		r1[col["alerted"]] != "true" || r1[col["cached"]] != "false" {
		t.Errorf("row1 %v", r1)
	}
	if r2[col["threat_factor"]] != "" || r2[col["quarantined_to"]] != "" ||
		r2[col["alerted"]] != "" {
		t.Errorf("row2 %v", r2)
	}
}

func TestWriteReportsFallback(t *testing.T) {
	cwd := t.TempDir()
	old, _ := os.Getwd()
	os.Chdir(cwd)
	defer os.Chdir(old)
	out := map[string]any{"results": []map[string]any{}}
	bad := filepath.Join(cwd, "nonexistent", "dir")
	writeReports(out, bad, "rep.json",
		map[string]bool{"json": true, "csv": true, "html": true},
		newLogger(false, "", 0, 0))
	if _, err := os.Stat(filepath.Join(cwd, "rep.json")); err != nil {
		t.Fatalf("fallback JSON not written to cwd: %v", err)
	}
	// Primary works: no fallback file.
	good := t.TempDir()
	os.Remove(filepath.Join(cwd, "rep.json"))
	writeReports(out, good, "rep.json", map[string]bool{"json": true},
		newLogger(false, "", 0, 0))
	if _, err := os.Stat(filepath.Join(good, "rep.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cwd, "rep.json")); err == nil {
		t.Fatal("fallback used although primary succeeded")
	}
}

func TestRunScopedVerdictsAndOutput(t *testing.T) {
	db := newTestDB(t)
	db.UpsertPending("old", "/old", "old", 1)
	db.MarkDoneDirect("old", "malicious", "T", nil, nil, "fie")
	db.q(`UPDATE uploads SET updated_at='2000-01-01 00:00:00'`)
	db.q(`UPDATE uploads SET status='failed', error='x' WHERE sha256='old'`)
	since := db.Now()
	time.Sleep(10 * time.Millisecond)
	db.UpsertPending("new", "/new", "new", 1)
	db.MarkDoneDirect("new", "goodware", "", nil, nil, "fie")
	db.MarkActions("new", "/q/new", true)
	if n := len(db.Verdicts(since)); n != 1 {
		t.Fatalf("scoped rows=%d want 1", n)
	}
	if n := len(db.Verdicts("")); n != 2 {
		t.Fatalf("all rows=%d want 2", n)
	}
	a := &Args{}
	out := buildOutputFromDB(a, db, NewCounters(), "/", 2, nil, since)
	res := resultsList(out)
	if len(res) != 1 || res[0]["quarantined_to"] != "/q/new" || res[0]["alerted"] != true {
		t.Fatalf("results %v", res)
	}
	s := out["summary"].(map[string]any)
	if s["files_with_errors"] != 1 {
		t.Fatalf("summary %v", s)
	}
}

// M9: the HTML Quarantined column is HTML-escaped (a crafted file name lands
// in quarantined_to verbatim).
func TestHTMLQuarantinedColumnEscaped(t *testing.T) {
	out := map[string]any{"results": []map[string]any{{
		"file_path": "a", "classification": "malicious",
		"quarantined_to": "/q/<script>alert(1)</script>&x",
		"api":            map[string]any{"status": "completed"},
	}}}
	p := filepath.Join(t.TempDir(), "r.html")
	if err := writeHTMLReport(out, p, newLogger(false, "", 0, 0)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := string(b)
	if strings.Contains(h, "<script>alert(1)") {
		t.Fatal("quarantined_to not escaped")
	}
	if !strings.Contains(h, "/q/&lt;script&gt;alert(1)&lt;/script&gt;&amp;x") {
		t.Fatal("escaped quarantined_to missing from HTML")
	}
}
