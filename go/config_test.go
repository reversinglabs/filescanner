// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// config_test.go — mirror of tests/test_config.py for the new multi-backend
// sections: defaults, parsing + ${ENV} expansion, backend validation,
// enum fallbacks, batch_size clamp.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeINI(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigBackendDefaults(t *testing.T) {
	// Absent backend sections must yield spec defaults so existing
	// detect-only configs keep working unchanged.
	a, err := loadConfig(writeINI(t,
		"[detect]\nhost = https://x\ntoken = t\n[scan]\ndrive = E:\\\n"))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"backend", a.Backend, "detect"},
		{"fie_host", a.FieHost, ""},
		{"fie_mode", a.FieMode, "hash_then_scan"},
		{"fie_trust_ok", a.FieTrustOK, false},
		{"fie_external_id", a.FieExternalID, "rel_path"},
		{"a1000_analysis", a.A1000Analysis, "cloud"},
		{"a1000_report_detail", a.A1000ReportDetail, "summary"},
		{"ticloud_host", a.TicloudHost, "https://data.reversinglabs.com"},
		{"ticloud_upload_timeout", a.TicloudUploadTimeout, 300},
		{"ticloud_min_interval_ms", a.TicloudMinIntervalMs, 100},
		{"ticloud_extended", a.TicloudExtended, true},
		{"reputation_precheck", a.ReputationPrecheck, false},
		{"reputation_batch_size", a.ReputationBatchSize, 100},
		{"reputation_skip_classified", a.ReputationSkipClassified, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadConfigBackendSectionsParsed(t *testing.T) {
	t.Setenv("A1000_TOKEN", "tok1")
	t.Setenv("TICLOUD_USER", "u1")
	t.Setenv("TICLOUD_PASS", "p1")
	a, err := loadConfig(writeINI(t, `
[scan]
backend = a1000
drive = E:\
[fie]
host = http://fie.local:8000
mode = hash_only
trust_ok = true
external_id = filename
[a1000]
host = https://a1000.example.com
token = ${A1000_TOKEN}
analysis = local
tags = usb,batch1
comment = hello
archive_password = infected
sandbox_platform = windows10
report_detail = full
[ticloud]
host = https://ticloud.example.com
username = ${TICLOUD_USER}
password = ${TICLOUD_PASS}
domain = corp.local
archive_password = infected
upload_timeout = 600
min_interval_ms = 250
extended = false
[reputation]
precheck = true
batch_size = 50
skip_classified = false
`))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"backend", a.Backend, "a1000"},
		{"fie_host", a.FieHost, "http://fie.local:8000"},
		{"fie_mode", a.FieMode, "hash_only"},
		{"fie_trust_ok", a.FieTrustOK, true},
		{"fie_external_id", a.FieExternalID, "filename"},
		{"a1000_host", a.A1000Host, "https://a1000.example.com"},
		{"a1000_token", a.A1000Token, "tok1"}, // env var expanded
		{"a1000_analysis", a.A1000Analysis, "local"},
		{"a1000_tags", a.A1000Tags, "usb,batch1"},
		{"a1000_comment", a.A1000Comment, "hello"},
		{"a1000_archive_password", a.A1000ArchivePassword, "infected"},
		{"a1000_sandbox_platform", a.A1000SandboxPlatform, "windows10"},
		{"a1000_report_detail", a.A1000ReportDetail, "full"},
		{"ticloud_host", a.TicloudHost, "https://ticloud.example.com"},
		{"ticloud_username", a.TicloudUsername, "u1"},
		{"ticloud_password", a.TicloudPassword, "p1"},
		{"ticloud_domain", a.TicloudDomain, "corp.local"},
		{"ticloud_archive_password", a.TicloudArchivePassword, "infected"},
		{"ticloud_upload_timeout", a.TicloudUploadTimeout, 600},
		{"ticloud_min_interval_ms", a.TicloudMinIntervalMs, 250},
		{"ticloud_extended", a.TicloudExtended, false},
		{"reputation_precheck", a.ReputationPrecheck, true},
		{"reputation_batch_size", a.ReputationBatchSize, 50},
		{"reputation_skip_classified", a.ReputationSkipClassified, false},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestLoadConfigUnknownBackendFails(t *testing.T) {
	// An unknown backend would run the whole pipeline against a client that
	// does not exist — fail at startup, not after the first upload.
	_, err := loadConfig(writeINI(t, "[scan]\nbackend = bogus\n"))
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestLoadConfigInvalidEnumsFallBack(t *testing.T) {
	// Non-backend enum typos warn + use the default (same convention as
	// cleanup_old_records/read_speed_test); only scan.backend is fatal.
	a, err := loadConfig(writeINI(t, `
[fie]
mode = bogus
external_id = bogus
[a1000]
report_detail = bogus
`))
	if err != nil {
		t.Fatal(err)
	}
	if a.FieMode != "hash_then_scan" {
		t.Errorf("fie_mode = %q", a.FieMode)
	}
	if a.FieExternalID != "rel_path" {
		t.Errorf("fie_external_id = %q", a.FieExternalID)
	}
	if a.A1000ReportDetail != "summary" {
		t.Errorf("a1000_report_detail = %q", a.A1000ReportDetail)
	}
}

func TestLoadConfigReputationBatchSizeClamped(t *testing.T) {
	// TCA-0101 bulk accepts at most 100 hashes per call — a larger
	// batch_size would make every pre-check batch fail server-side.
	a, err := loadConfig(writeINI(t, "[reputation]\nbatch_size = 500\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.ReputationBatchSize != 100 {
		t.Errorf("batch_size = %d, want 100", a.ReputationBatchSize)
	}
}

func TestLoadConfigA1000AnalysisEmptyMeansLocal(t *testing.T) {
	// An explicitly empty 'analysis' field means local-only analysis — it
	// must not silently fall back to the 'cloud' default.
	a, err := loadConfig(writeINI(t, "[a1000]\nhost = https://a\nanalysis =\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.A1000Analysis != "" {
		t.Errorf("a1000_analysis = %q, want empty", a.A1000Analysis)
	}
}

// analysis_depth / large_file_threshold / detect_file_type /
// max_enrich_bytes / extract_strings / extract_iocs have no backend
// API parameter: a non-default value warns "<key> is currently a no-op".
func TestNoopConfigWarnings(t *testing.T) {
	def := &Args{AnalysisDepth: "full", LargeFileThreshold: 1_000_000_000,
		DetectFileType: true, MaxEnrichBytes: DefaultMaxEnrichBytes}
	if w := noopConfigKeys(def); len(w) != 0 {
		t.Fatalf("defaults must not warn: %v", w)
	}
	set := &Args{AnalysisDepth: "quick", LargeFileThreshold: 5,
		DetectFileType: false, MaxEnrichBytes: 7, ExtractStrings: true,
		ExtractIOCs: true}
	w := noopConfigKeys(set)
	want := []string{"analysis_depth", "large_file_threshold",
		"detect_file_type", "max_enrich_bytes", "extract_strings",
		"extract_iocs"}
	if strings.Join(w, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", w, want)
	}
	// Empty analysis_depth means "full" (Python `or "full"`) — no warning.
	p := filepath.Join(t.TempDir(), "c.ini")
	os.WriteFile(p, []byte("[scan]\nanalysis_depth =\n"), 0o644)
	a, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.AnalysisDepth != "full" || len(noopConfigKeys(a)) != 0 {
		t.Fatalf("empty analysis_depth: got %q %v", a.AnalysisDepth,
			noopConfigKeys(a))
	}
}
