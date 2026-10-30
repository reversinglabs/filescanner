// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// config.go — INI loading mirroring filescanner.py's load_config().
// Same sections/keys, same defaults, same ${ENV_VAR} expansion and
// inline '#' / ';' comments.
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const ScriptVersion = "1.0.0-go"
const OutputFilename = "spectra_detect_scan_results.json"
const StateFilename = ".scan_state.json"
const AlertsFilename = "alerts.ndjson"
const LogFilename = "spectra_detect_scan.log"

const IOChunkSize = 1 << 20
const DefaultMaxEnrichBytes = 25 * 1024 * 1024

// HeadCaptureBytes: detectFileType only inspects the first 4 KiB, so the
// hashing pass captures at most this much (Python HEAD_CAPTURE_BYTES).
const HeadCaptureBytes = 4096

// DefaultLargeFileThreshold mirrors Python DEFAULT_LARGE_FILE_THRESHOLD.
const DefaultLargeFileThreshold = 1_000_000_000

var skipFiles = map[string]bool{
	OutputFilename: true, StateFilename: true, AlertsFilename: true, LogFilename: true,
}
var skipDirs = map[string]bool{
	"System Volume Information": true, "$RECYCLE.BIN": true, "$WinREAgent": true,
}

// ---- extension presets ---------------------------------------------------

var executableExts = strSet(".exe", ".dll", ".sys", ".drv", ".com", ".bat",
	".cmd", ".ps1", ".scr", ".msi", ".msp", ".cpl", ".ocx", ".vbs", ".vbe",
	".js", ".jse", ".wsf", ".wsh", ".hta", ".inf", ".reg", ".lnk", ".pif",
	".jar", ".apk")
var documentExts = strSet(".doc", ".docx", ".dot", ".dotx", ".xls", ".xlsx",
	".xlsm", ".xltx", ".ppt", ".pptx", ".pdf", ".rtf", ".txt", ".csv",
	".odt", ".ods", ".odp")
var archiveExts = strSet(".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
	".iso", ".img", ".cab", ".arj", ".lzh", ".uue", ".z", ".sit", ".ace", ".alz")
var mediaExts = strSet(".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
	".webp", ".ico", ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flac",
	".wav", ".ogg")
var scriptWebExts = strSet(".html", ".htm", ".xml", ".php", ".asp", ".aspx",
	".jsp", ".cgi", ".py", ".rb", ".pl", ".pm", ".sh", ".bash", ".zsh", ".ksh")

var allDefaultExts = unionSets(executableExts, documentExts, archiveExts,
	mediaExts, scriptWebExts)

var extPresets = map[string]map[string]bool{
	"executables": executableExts, "documents": documentExts,
	"archives": archiveExts, "media": mediaExts,
	"scripts-web": scriptWebExts, "all": allDefaultExts,
}

var fileTypeCategories = strSet("pe", "elf", "macho", "java-class", "pdf",
	"ole", "zip", "rar", "7z", "gzip", "bzip2", "xz", "cab", "jpeg", "png",
	"gif", "bmp", "tiff", "script", "text", "data", "empty", "unreadable")

func strSet(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}
func unionSets(sets ...map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, s := range sets {
		for k := range s {
			out[k] = true
		}
	}
	return out
}

func setDiff(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if !b[k] {
			out[k] = true
		}
	}
	return out
}
func setInter(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}
func setKeys(s map[string]bool) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

// ---- Args (mirror of the Python argparse.Namespace) -----------------------

type Args struct {
	// [detect]
	Host, Token, Proxy string
	NoVerifySSL        bool
	// [scan]
	Drive                                         string
	Extensions, ExcludeExtensions, Preset         string
	FileTypesRaw                                  string
	AnalysisDepth                                 string
	DetectFileType, ExtractStrings, ExtractIOCs   bool
	MinStringLen, MaxStrings, MaxIOCs             int
	MaxEnrichBytes, LargeFileThreshold            int
	ReadSpeedTest                                 string
	MinReadMbps, ReadTestMaxBytes, ReadTestMaxSec int
	MaxFiles                                      int
	Backend                                       string
	// [fie]
	FieHost, FieMode, FieExternalID string
	FieTrustOK                      bool
	// [a1000]
	A1000Host, A1000Token, A1000Analysis, A1000Tags, A1000Comment string
	A1000ArchivePassword, A1000SandboxPlatform, A1000ReportDetail string
	// [ticloud]
	TicloudHost, TicloudUsername, TicloudPassword, TicloudDomain string
	TicloudArchivePassword                                       string
	TicloudUploadTimeout, TicloudMinIntervalMs                   int
	TicloudExtended                                              bool
	// [reputation]
	ReputationPrecheck       bool
	ReputationBatchSize      int
	ReputationSkipClassified bool
	// [pipeline]
	UploadWorkers, ResultPollers, ResultPollInterval int
	ReportWaitHours, MaxInFlight, ProgressEvery      int
	AvailProbeSeconds                                int
	// [backoff]
	BackoffBase, BackoffMax, UploadRetryWindow          int
	MaxUploadAttempts, ReadyCheckInterval, ReadyMaxWait int
	// [database]
	DBPath            string
	RetentionDays     int
	CleanupOldRecords string
	StoreFullReport   bool
	// [actions]
	Resume                                           bool
	SkipHiddenDirs                                   bool
	QuarantineAction, QuarantineDir, QuarantineOnRaw string
	AlertOnRaw, AlertWebhook, AlertSyslog            string
	AlertEventlog                                    bool
	// [output]
	OutputDir, Output, ReportFormatsRaw string
	SummaryOnly, Verbose                bool
	LogMaxMB, LogBackups                int

	// normalized sets (filled by normalizeArgs)
	FileTypesSet, QuarantineOn, AlertOn, ReportFormats map[string]bool
}

var envVarRe = regexp.MustCompile(`\$\{([^}]*)\}`)

func expandEnv(v string) string {
	return envVarRe.ReplaceAllStringFunc(v, func(m string) string {
		return os.Getenv(envVarRe.FindStringSubmatch(m)[1])
	})
}

// ---- minimal INI parser --------------------------------------------------
// Sections "[name]", "key = value" pairs; '#' and ';' start an inline
// comment when preceded by whitespace (matches configparser
// inline_comment_prefixes). No interpolation.

type iniFile map[string]map[string]string // section -> key -> value

var iniCommentRe = regexp.MustCompile(`[ \t]+[#;].*$`)

func parseINI(path string) (iniFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := iniFile{}
	sec := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			sec = strings.ToLower(strings.TrimSpace(line[1:strings.Index(line, "]")]))
			if out[sec] == nil {
				out[sec] = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			k, v, ok = strings.Cut(line, ":")
			if !ok {
				continue
			}
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := iniCommentRe.ReplaceAllString(v, "")
		out[sec][key] = expandEnv(strings.TrimSpace(val))
	}
	return out, sc.Err()
}

func (in iniFile) has(sec, key string) bool {
	_, ok := in[sec][key]
	return ok
}
func (in iniFile) g(sec, key, def string) string {
	if v, ok := in[sec][key]; ok {
		return v
	}
	return def
}
func (in iniFile) gi(sec, key string, def int, log *Logger) int {
	v := in.g(sec, key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Warn("Invalid int for %s.%s=%q; using %d", sec, key, v, def)
		return def
	}
	return n
}
func (in iniFile) gb(sec, key string, def bool) bool {
	v := in.g(sec, key, "")
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// noopConfigKeys lists the no-op settings configured to a non-default value.
func noopConfigKeys(a *Args) []string {
	var keys []string
	if a.AnalysisDepth != "full" {
		keys = append(keys, "analysis_depth")
	}
	if a.LargeFileThreshold != DefaultLargeFileThreshold {
		keys = append(keys, "large_file_threshold")
	}
	if !a.DetectFileType {
		keys = append(keys, "detect_file_type")
	}
	if a.MaxEnrichBytes != DefaultMaxEnrichBytes {
		keys = append(keys, "max_enrich_bytes")
	}
	if a.ExtractStrings {
		keys = append(keys, "extract_strings")
	}
	if a.ExtractIOCs {
		keys = append(keys, "extract_iocs")
	}
	return keys
}

func loadConfig(path string) (*Args, error) {
	in, err := parseINI(path)
	if err != nil {
		return nil, err
	}
	log := newLogger(false, "", 0, 0)
	a := &Args{}

	a.Host = in.g("detect", "host", "")
	a.Token = in.g("detect", "token", "")
	a.Proxy = in.g("detect", "proxy", "")
	a.NoVerifySSL = in.gb("detect", "no_verify_ssl", false)

	a.Drive = in.g("scan", "drive", "")
	a.Extensions = in.g("scan", "extensions", "")
	a.ExcludeExtensions = in.g("scan", "exclude_extensions", "")
	a.Preset = in.g("scan", "preset", "")
	a.SkipHiddenDirs = in.gb("scan", "skip_hidden_dirs", false)
	a.FileTypesRaw = in.g("scan", "file_types", "")
	a.AnalysisDepth = in.g("scan", "analysis_depth", "full")
	if a.AnalysisDepth == "" {
		a.AnalysisDepth = "full" // empty means default (Python `or "full"`)
	}
	a.DetectFileType = in.gb("scan", "detect_file_type", true)
	a.ExtractStrings = in.gb("scan", "extract_strings", false)
	a.ExtractIOCs = in.gb("scan", "extract_iocs", false)
	a.MinStringLen = in.gi("scan", "min_string_len", 6, log)
	a.MaxStrings = in.gi("scan", "max_strings", 200, log)
	a.MaxIOCs = in.gi("scan", "max_iocs", 100, log)
	a.MaxEnrichBytes = in.gi("scan", "max_enrich_bytes", DefaultMaxEnrichBytes, log)
	a.LargeFileThreshold = in.gi("scan", "large_file_threshold",
		DefaultLargeFileThreshold, log)
	a.ReadSpeedTest = strings.ToLower(in.g("scan", "read_speed_test", "ask"))
	a.MinReadMbps = in.gi("scan", "min_read_mbps", 1, log)
	a.ReadTestMaxBytes = in.gi("scan", "read_test_max_bytes", 64<<20, log)
	a.ReadTestMaxSec = in.gi("scan", "read_test_max_seconds", 10, log)
	a.MaxFiles = in.gi("scan", "max_files", 0, log)
	a.Backend = strings.ToLower(in.g("scan", "backend", "detect"))
	if a.Backend == "" {
		a.Backend = "detect"
	}

	// No backend API parameter exists for these: say so instead of
	// silently ignoring a non-default value (checked on the configured
	// values, before normalizeArgs forces detect_file_type on).
	for _, k := range noopConfigKeys(a) {
		log.Warn("%s is currently a no-op", k)
	}

	a.UploadWorkers = in.gi("pipeline", "upload_workers", 10, log)
	a.ResultPollers = in.gi("pipeline", "result_pollers", 1, log)
	a.ResultPollInterval = in.gi("pipeline", "result_poll_interval", 2, log)
	a.ReportWaitHours = in.gi("pipeline", "report_wait_hours", 12, log)
	a.MaxInFlight = in.gi("pipeline", "max_in_flight", 10000, log)
	a.ProgressEvery = in.gi("pipeline", "progress_every", 100, log)
	a.AvailProbeSeconds = in.gi("pipeline", "avail_probe_seconds", 20, log)
	if !in.has("pipeline", "upload_workers") {
		if lw := in.gi("output", "workers", 0, log); lw > 0 {
			a.UploadWorkers = lw // legacy [output] workers alias
		}
	}

	a.BackoffBase = in.gi("backoff", "base_seconds", 2, log)
	a.BackoffMax = in.gi("backoff", "max_seconds", 60, log)
	a.UploadRetryWindow = in.gi("backoff", "upload_retry_window", 600, log)
	a.MaxUploadAttempts = in.gi("backoff", "max_upload_attempts", 8, log)
	a.ReadyCheckInterval = in.gi("backoff", "ready_check_interval", 5, log)
	a.ReadyMaxWait = in.gi("backoff", "ready_max_wait", 300, log)

	a.DBPath = in.g("database", "path", "scan_state.db")
	a.RetentionDays = in.gi("database", "retention_days", 7, log)
	a.CleanupOldRecords = strings.ToLower(in.g("database", "cleanup_old_records", "ask"))
	a.StoreFullReport = in.gb("database", "store_full_report", false)

	a.Resume = in.gb("actions", "resume", true)
	a.QuarantineAction = in.g("actions", "quarantine_action", "none")
	a.QuarantineDir = in.g("actions", "quarantine_dir", "")
	a.QuarantineOnRaw = in.g("actions", "quarantine_on", "malicious")
	a.AlertOnRaw = in.g("actions", "alert_on", "malicious,suspicious")
	a.AlertWebhook = in.g("actions", "alert_webhook", "")
	a.AlertSyslog = in.g("actions", "alert_syslog", "")
	a.AlertEventlog = in.gb("actions", "alert_eventlog", false)

	a.OutputDir = in.g("output", "output_dir", "")
	a.Output = in.g("output", "output", OutputFilename)
	a.ReportFormatsRaw = in.g("output", "report_formats", "json,csv,html,pdf")
	a.SummaryOnly = in.gb("output", "summary_only", false)
	a.Verbose = in.gb("output", "verbose", false)
	a.LogMaxMB = in.gi("output", "log_max_mb", 50, log)
	a.LogBackups = in.gi("output", "log_backups", 5, log)

	a.FieHost = in.g("fie", "host", "")
	a.FieMode = strings.ToLower(in.g("fie", "mode", "hash_then_scan"))
	if a.FieMode == "" {
		a.FieMode = "hash_then_scan"
	}
	switch a.FieMode {
	case "scan", "hash_then_scan", "hash_only":
	default:
		log.Warn("fie.mode=%q invalid; using 'hash_then_scan'", a.FieMode)
		a.FieMode = "hash_then_scan"
	}
	a.FieTrustOK = in.gb("fie", "trust_ok", false)
	a.FieExternalID = strings.ToLower(in.g("fie", "external_id", "rel_path"))
	if a.FieExternalID == "" {
		a.FieExternalID = "rel_path"
	}
	switch a.FieExternalID {
	case "rel_path", "filename", "none":
	default:
		log.Warn("fie.external_id=%q invalid; using 'rel_path'", a.FieExternalID)
		a.FieExternalID = "rel_path"
	}

	a.A1000Host = in.g("a1000", "host", "")
	a.A1000Token = in.g("a1000", "token", "")
	a.A1000Analysis = in.g("a1000", "analysis", "cloud")
	a.A1000Tags = in.g("a1000", "tags", "")
	a.A1000Comment = in.g("a1000", "comment", "")
	a.A1000ArchivePassword = in.g("a1000", "archive_password", "")
	a.A1000SandboxPlatform = in.g("a1000", "sandbox_platform", "")
	a.A1000ReportDetail = strings.ToLower(in.g("a1000", "report_detail", "summary"))
	if a.A1000ReportDetail == "" {
		a.A1000ReportDetail = "summary"
	}
	switch a.A1000ReportDetail {
	case "summary", "full":
	default:
		log.Warn("a1000.report_detail=%q invalid; using 'summary'", a.A1000ReportDetail)
		a.A1000ReportDetail = "summary"
	}

	a.TicloudHost = in.g("ticloud", "host", "https://data.reversinglabs.com")
	if a.TicloudHost == "" {
		a.TicloudHost = "https://data.reversinglabs.com"
	}
	a.TicloudUsername = in.g("ticloud", "username", "")
	a.TicloudPassword = in.g("ticloud", "password", "")
	a.TicloudDomain = in.g("ticloud", "domain", "")
	a.TicloudArchivePassword = in.g("ticloud", "archive_password", "")
	a.TicloudUploadTimeout = in.gi("ticloud", "upload_timeout", 300, log)
	a.TicloudMinIntervalMs = in.gi("ticloud", "min_interval_ms", 100, log)
	a.TicloudExtended = in.gb("ticloud", "extended", true)

	a.ReputationPrecheck = in.gb("reputation", "precheck", false)
	a.ReputationBatchSize = in.gi("reputation", "batch_size", 100, log)
	if a.ReputationBatchSize > 100 {
		log.Warn("reputation.batch_size=%d exceeds API max 100; clamping",
			a.ReputationBatchSize)
		a.ReputationBatchSize = 100
	}
	a.ReputationSkipClassified = in.gb("reputation", "skip_classified", true)

	if strings.ToLower(a.Extensions) == "all" {
		a.Extensions = ""
	}
	switch a.Backend {
	case "detect", "a1000", "fie", "cloud":
	default:
		return nil, fmt.Errorf("scan.backend=%q invalid; valid: detect|a1000|fie|cloud",
			a.Backend)
	}
	return a, nil
}

func csvSet(v string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out[p] = true
		}
	}
	return out
}

func parseExtList(v string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, ".") {
			p = "." + p
		}
		out[p] = true
	}
	return out
}

// determineExtensions: nil => no filter (scan everything).
func determineExtensions(a *Args) map[string]bool {
	if a.ExcludeExtensions != "" {
		return setDiff(allDefaultExts, parseExtList(a.ExcludeExtensions))
	}
	if a.Extensions != "" {
		exts := parseExtList(a.Extensions)
		if len(exts) == 1 {
			for k := range exts {
				if preset, ok := extPresets[strings.TrimPrefix(k, ".")]; ok {
					return preset
				}
			}
		}
		return exts
	}
	if a.Preset != "" {
		return extPresets[a.Preset]
	}
	return nil
}

// normalizeArgs returns an exit-code-bearing error message or "" on success.
func normalizeArgs(a *Args, log *Logger) string {
	a.FileTypesSet = csvSet(a.FileTypesRaw)
	for ft := range a.FileTypesSet {
		if !fileTypeCategories[ft] {
			log.Warn("Ignoring unknown file_types: %s", ft)
			delete(a.FileTypesSet, ft)
		}
	}
	if len(a.FileTypesSet) > 0 && !a.DetectFileType {
		log.Info("file_types requires file-type detection; enabling it.")
		a.DetectFileType = true
	}
	a.QuarantineOn = csvSet(a.QuarantineOnRaw)
	a.AlertOn = csvSet(a.AlertOnRaw)

	fmts := csvSet(a.ReportFormatsRaw)
	valid := strSet("json", "csv", "html", "pdf")
	for f := range fmts {
		if !valid[f] {
			log.Warn("Ignoring unknown report_formats: %s", f)
			delete(fmts, f)
		}
	}
	if len(fmts) == 0 {
		fmts = map[string]bool{"json": true}
	}
	a.ReportFormats = fmts

	if a.UploadWorkers < 1 {
		a.UploadWorkers = 1
	}
	if a.ResultPollers < 1 {
		a.ResultPollers = 1
	}
	if a.CleanupOldRecords != "ask" && a.CleanupOldRecords != "always" && a.CleanupOldRecords != "never" {
		log.Warn("cleanup_old_records=%q invalid; using 'ask'", a.CleanupOldRecords)
		a.CleanupOldRecords = "ask"
	}
	if a.ReadSpeedTest != "ask" && a.ReadSpeedTest != "always" && a.ReadSpeedTest != "off" {
		log.Warn("read_speed_test=%q invalid; using 'ask'", a.ReadSpeedTest)
		a.ReadSpeedTest = "ask"
	}
	if a.QuarantineAction != "none" && a.QuarantineAction != "copy" && a.QuarantineAction != "move" {
		log.Warn("quarantine_action=%q invalid; using 'none'", a.QuarantineAction)
		a.QuarantineAction = "none"
	}
	if a.Preset != "" {
		if _, ok := extPresets[a.Preset]; !ok {
			var names []string
			for k := range extPresets {
				names = append(names, k)
			}
			return fmt.Sprintf("preset=%q invalid; valid presets: %s", a.Preset,
				strings.Join(names, ", "))
		}
	}
	if a.Host == "" || a.Token == "" || a.Drive == "" {
		return "config.ini missing required detect.host/detect.token/scan.drive"
	}
	return ""
}
