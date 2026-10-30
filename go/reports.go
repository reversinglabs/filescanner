// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// reports.go — output assembly from ScanDB + JSON/CSV/HTML writers.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func buildMetadata(a *Args, driveRoot string, total int,
	include map[string]bool) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339)
	return map[string]any{
		"scan_started_at":          now,
		"scanner_version":          ScriptVersion,
		"usb_drive_root":           driveRoot,
		"spectra_detect_host":      a.Host,
		"total_files_identified":   total,
		"workers":                  a.UploadWorkers,
		"extension_filter_enabled": include != nil,
		"extension_filter_values":  sortedKeys(include),
		"file_type_filter":         sortedKeys(a.FileTypesSet),
		"analysis_depth":           a.AnalysisDepth,
		"enrichment": map[string]any{
			"detect_file_type": a.DetectFileType,
			"extract_strings":  a.ExtractStrings,
			"extract_iocs":     a.ExtractIOCs,
			"max_enrich_bytes": a.MaxEnrichBytes,
		},
		"resume_enabled":       a.Resume,
		"quarantine_action":    a.QuarantineAction,
		"quarantine_on":        sortedKeys(a.QuarantineOn),
		"alert_on":             sortedKeys(a.AlertOn),
		"upload_workers":       a.UploadWorkers,
		"result_poll_interval": a.ResultPollInterval,
		"report_wait_hours":    a.ReportWaitHours,
		"max_in_flight":        a.MaxInFlight,
		"ssl_verification":     !a.NoVerifySSL,
		"timestamp":            now,
	}
}

func buildOutputFromDB(a *Args, db *ScanDB, counters *Counters,
	driveRoot string, total int, include map[string]bool,
	runStartedAt string) map[string]any {
	metadata := buildMetadata(a, driveRoot, total, include)
	c := counters.Snapshot()
	var results []map[string]any
	completed := 0
	// Summary cards are derived from the rows in this report (not per-run
	// counters) so header and table always agree. Buckets mirror
	// verdictActions over done/cached rows; errors = failed/timeout rows
	// minus file-type skips (drives the exit code).
	n := map[string]int{}
	for _, r := range db.Verdicts(runStartedAt) {
		if r.Status == "done" || r.Status == "cached" {
			switch r.Classification {
			case "malicious", "suspicious", "goodware", "unknown":
				n[r.Classification]++
			default:
				n["other"]++
			}
		}
		skipped := strings.HasPrefix(r.Error, "skipped_filetype:")
		if (r.Status == "failed" || r.Status == "timeout") && !skipped {
			n["errors"]++
		}
		if r.Status == "cached" {
			n["cached"]++
		}
		if r.QuarantinedTo != "" {
			n["quarantined"]++
		}
		if r.Alerted != nil && *r.Alerted == 1 {
			n["alerts"]++
		}
		var report any
		if r.ReportJSON != "" && !a.SummaryOnly {
			var p map[string]any
			if err := json.Unmarshal([]byte(r.ReportJSON), &p); err == nil {
				report = p
			}
		}
		status := r.Status
		if status == "done" {
			status = "completed"
		}
		if status == "completed" || status == "cached" {
			completed++
		}
		cls := r.Classification
		if cls == "" {
			cls = "unavailable"
		}
		results = append(results, map[string]any{
			"file_path":       r.RelPath,
			"absolute_path":   r.FilePath,
			"file_name":       filepath.Base(r.FilePath),
			"file_extension":  strings.ToLower(filepath.Ext(r.FilePath)),
			"file_size_bytes": r.FileSize,
			"file_type":       nil,
			"sha256":          r.Sha256,
			"classification":  cls,
			"threat_name":     nilIfEmpty(r.ThreatName),
			"threat_factor":   r.ThreatFactor,
			"cached":          r.Status == "cached",
			"quarantined_to":  nilIfEmpty(r.QuarantinedTo),
			"alerted":         alertedValue(r.Alerted),
			"api":             map[string]any{"status": status, "error": nilIfEmpty(r.Error), "report": report},
		})
	}
	return map[string]any{
		"scan_metadata": metadata,
		"summary": map[string]any{
			"total_files_matched_filter":   total,
			"files_processed":              len(results),
			"files_completed_successfully": completed,
			// scoped failed/timeout rows + failed/timeout rows from earlier
			// runs this run never touched (counted, not listed).
			"files_with_errors":   n["errors"] + db.StaleErrorRows(runStartedAt),
			"cached_hits":         n["cached"],
			"skipped_by_filetype": c["skipped_filetype"],
			"quarantined":         n["quarantined"],
			"alerts":              n["alerts"],
			"malicious":           n["malicious"],
			"suspicious":          n["suspicious"],
			"goodware":            n["goodware"],
			"unknown":             n["unknown"],
			"other":               n["other"],
			// Upload/skip events: run counters (as in Python).
			"uploads_submitted": c["submitted"],
		},
		"results": results,
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func resultsList(output map[string]any) []map[string]any {
	out := []map[string]any{}
	if rs, ok := output["results"].([]map[string]any); ok {
		return rs
	}
	if rs, ok := output["results"].([]any); ok {
		for _, r := range rs {
			if m, ok := r.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func alertedValue(a *int64) any {
	if a == nil {
		return nil
	}
	return *a == 1
}

// csvSafe neutralises spreadsheet formula injection: cells starting with
// = + - @ TAB CR get a leading apostrophe.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func writeJSONReport(output map[string]any, path string, log *Logger) error {
	data, err := json.MarshalIndent(output, "", "  ")
	if err == nil {
		err = os.WriteFile(path, data, 0o644)
	}
	if err != nil {
		log.Error("Failed to write json report: %v", err)
		return err
	}
	log.Info("Wrote JSON report: %s", path)
	return nil
}

func writeCSVReport(output map[string]any, path string, log *Logger) error {
	cols := []string{"file_path", "file_name", "file_extension", "file_type",
		"file_size_bytes", "sha256", "classification", "threat_name",
		"threat_factor", "cached", "quarantined_to", "alerted",
		"api_status", "api_error", "num_iocs", "num_strings"}
	f, err := os.Create(path)
	if err != nil {
		log.Error("Failed to write csv report: %v", err)
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	hdr := make([]string, len(cols))
	for i, c := range cols {
		hdr[i] = csvSafe(c)
	}
	w.Write(hdr)
	for _, r := range resultsList(output) {
		api, _ := r["api"].(map[string]any)
		numIOCs := 0
		if iocs, ok := r["iocs"].(map[string]any); ok {
			for k, v := range iocs {
				if lst, ok := v.([]any); ok && k != "urls_defanged" {
					numIOCs += len(lst)
				}
			}
		}
		row := []string{
			str(r["file_path"]), str(r["file_name"]), str(r["file_extension"]),
			str(r["file_type"]), str(r["file_size_bytes"]), str(r["sha256"]),
			str(r["classification"]), str(r["threat_name"]),
			str(r["threat_factor"]), str(r["cached"]),
			str(r["quarantined_to"]), str(r["alerted"]),
			str(api["status"]), str(api["error"]),
			fmt.Sprint(numIOCs), str(r["strings_total"]),
		}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		w.Write(row)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Error("Failed to write csv report: %v", err)
		return err
	}
	if err := f.Close(); err != nil {
		log.Error("Failed to write csv report: %v", err)
		return err
	}
	log.Info("Wrote CSV report: %s", path)
	return nil
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case *int64:
		if t == nil {
			return ""
		}
		return fmt.Sprint(*t)
	case *int:
		if t == nil {
			return ""
		}
		return fmt.Sprint(*t)
	case *float64:
		if t == nil {
			return ""
		}
		return fmt.Sprint(*t)
	case *bool:
		if t == nil {
			return ""
		}
		return fmt.Sprint(*t)
	case *string:
		if t == nil {
			return ""
		}
		return *t
	default:
		return fmt.Sprint(t)
	}
}

var htmlColors = map[string]string{
	"malicious": "#c0392b", "suspicious": "#d68910", "goodware": "#1e8449",
	"unknown": "#7f8c8d", "unavailable": "#95a5a6",
}

func writeHTMLReport(output map[string]any, path string, log *Logger) error {
	meta, _ := output["scan_metadata"].(map[string]any)
	summary, _ := output["summary"].(map[string]any)
	var rows strings.Builder
	for _, r := range resultsList(output) {
		cls := str(r["classification"])
		if cls == "" {
			cls = "unavailable"
		}
		color := htmlColors[cls]
		if color == "" {
			color = "#95a5a6"
		}
		numIOCs := 0
		if iocs, ok := r["iocs"].(map[string]any); ok {
			for _, v := range iocs {
				if lst, ok := v.([]any); ok {
					numIOCs += len(lst)
				}
			}
		}
		api, _ := r["api"].(map[string]any)
		quar := html.EscapeString(str(r["quarantined_to"]))
		sha := str(r["sha256"])
		if len(sha) > 16 {
			sha = sha[:16]
		}
		rows.WriteString("<tr>" +
			"<td class='mono'>" + html.EscapeString(str(r["file_path"])) + "</td>" +
			"<td>" + html.EscapeString(str(r["file_type"])) + "</td>" +
			"<td><span class='chip' style='background:" + color + "'>" +
			html.EscapeString(cls) + "</span></td>" +
			"<td>" + html.EscapeString(str(r["threat_name"])) + "</td>" +
			"<td class='mono'>" + html.EscapeString(sha) + "</td>" +
			fmt.Sprintf("<td>%d</td>", numIOCs) +
			"<td>" + html.EscapeString(str(api["status"])) + "</td>" +
			"<td>" + quar + "</td></tr>")
	}
	var cards strings.Builder
	for _, k := range []string{"files_processed", "malicious", "suspicious",
		"goodware", "unknown", "quarantined", "alerts", "files_with_errors"} {
		cards.WriteString(fmt.Sprintf(
			"<div class='card'><div class='num'>%v</div>"+
				"<div class='lbl'>%s</div></div>",
			summary[k], strings.ReplaceAll(k, "_", " ")))
	}
	// Styled after the RL release-notes template: logo + generator byline,
	// Roboto, RL red #f6143f accents on dark #373547 headers.
	doc := `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Spectra Detect Scan Report</title>
<style>
 body { font-family: Roboto, "Segoe UI", Arial, sans-serif; margin: 32px; color:#373547; }
 .topbar { display:flex; justify-content:space-between; align-items:flex-start;
           border-bottom:3px solid #f6143f; padding-bottom:14px; margin-bottom:18px; }
 .brand { color:#f6143f; font-size:26px; font-weight:700; letter-spacing:-0.5px; }
 .byline { color:#999999; font-size:11px; text-align:right; line-height:1.4; }
 h1 { font-size: 20px; color:#373547; margin: 8px 0 4px; }
 .meta { color:#666; font-size: 13px; margin-bottom: 18px; }
 .cards { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:22px; }
 .card { background:#efefef; border-radius:4px; padding:12px 16px; min-width:110px;
         border-top:3px solid #f6143f; }
 .card .num { font-size:24px; font-weight:700; color:#373547; }
 .card .lbl { font-size:11px; color:#666; text-transform:capitalize; }
 table { border-collapse: collapse; width:100%; font-size:13px; }
 th, td { text-align:left; padding:6px 8px; border-bottom:1px solid #efefef; }
 th { background:#373547; color:#fff; position:sticky; top:0; }
 .mono { font-family: Consolas, monospace; font-size:12px; }
 .chip { color:#fff; padding:2px 8px; border-radius:10px; font-size:12px; }
 .foot { margin-top:22px; padding-top:10px; border-top:1px solid #efefef;
         color:#999999; font-size:11px; }
</style></head><body>
<div class="topbar">
 <div class="brand">ReversingLabs</div>
 <div class="byline">Generated by filescanner<br>
 Open source &middot; MIT License</div>
</div>
<h1>Spectra Detect Scan Report</h1>
<div class="meta">
 Host: ` + html.EscapeString(str(meta["spectra_detect_host"])) + ` &middot;
 Drive: ` + html.EscapeString(str(meta["usb_drive_root"])) + ` &middot;
 Scanner v` + html.EscapeString(str(meta["scanner_version"])) + ` &middot;
 Started: ` + html.EscapeString(str(meta["scan_started_at"])) + `
</div>
<div class="cards">` + cards.String() + `</div>
<table>
<thead><tr><th>File</th><th>Type</th><th>Classification</th><th>Threat</th>
<th>SHA-256</th><th>IOCs</th><th>Status</th><th>Quarantined</th></tr></thead>
<tbody>` + rows.String() + `</tbody>
</table>
<div class="foot">Generated by filescanner (MIT License)</div>
</body></html>`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		log.Error("Failed to write html report: %v", err)
		return err
	}
	log.Info("Wrote HTML report: %s", path)
	return nil
}

// writeReports dispatches the configured formats; falls back to cwd/tmp so
// results are never silently lost.
func writeReports(output map[string]any, outputDir, baseName string,
	formats map[string]bool, log *Logger) {
	stem := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	wroteAny := false
	for _, fmt_ := range sortedKeys(formats) {
		var path string
		switch fmt_ {
		case "json":
			path = filepath.Join(outputDir, baseName)
		case "csv":
			path = filepath.Join(outputDir, stem+".csv")
		case "html":
			path = filepath.Join(outputDir, stem+".html")
		case "pdf":
			path = filepath.Join(outputDir, stem+".pdf")
		}
		var err error
		switch fmt_ {
		case "json":
			err = writeJSONReport(output, path, log)
		case "csv":
			err = writeCSVReport(output, path, log)
		case "html":
			err = writeHTMLReport(output, path, log)
		case "pdf":
			err = writePDFReport(output, path, log)
		}
		if err == nil {
			wroteAny = true
		}
	}
	if !wroteAny {
		for _, fallback := range []string{
			filepath.Join(mustCwd(), baseName),
			filepath.Join(os.TempDir(), baseName)} {
			log.Warn("Falling back to %s", fallback)
			if err := writeJSONReport(output, fallback, log); err == nil {
				return
			} else {
				log.Error("Fallback report write to %s failed: %v", fallback, err)
			}
		}
		log.Error("Could not write scan results to any location.")
	}
}

func mustCwd() string {
	d, _ := os.Getwd()
	return d
}
func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

var _ = sort.Strings // silence unused if refactored
