// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// pdf.go — dependency-free PDF/1.4 findings report, direct port of
// filescanner.py's write_pdf_report: landscape Letter, Courier columns,
// malicious/suspicious table only.
package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
)

var pdfColors = map[string][3]float64{ // RGB 0-1, mirrors htmlColors
	"malicious":   {0.75, 0.22, 0.17},
	"suspicious":  {0.84, 0.54, 0.06},
	"goodware":    {0.12, 0.52, 0.29},
	"unknown":     {0.50, 0.55, 0.55},
	"unavailable": {0.58, 0.65, 0.65},
}

var pdfFindings = []string{"malicious", "suspicious"}

var cp1252 = map[rune]byte{ // WinAnsi 0x80-0x9F range
	0x20AC: 0x80, 0x201A: 0x82, 0x0192: 0x83, 0x201E: 0x84, 0x2026: 0x85,
	0x2020: 0x86, 0x2021: 0x87, 0x02C6: 0x88, 0x2030: 0x89, 0x0160: 0x8A,
	0x2039: 0x8B, 0x0152: 0x8C, 0x017D: 0x8E, 0x2018: 0x91, 0x2019: 0x92,
	0x201C: 0x93, 0x201D: 0x94, 0x2022: 0x95, 0x2013: 0x96, 0x2014: 0x97,
	0x02DC: 0x98, 0x2122: 0x99, 0x0161: 0x9A, 0x203A: 0x9B, 0x0153: 0x9C,
	0x017E: 0x9E, 0x0178: 0x9F,
}

func pdfEsc(s string) string {
	// WinAnsi(cp1252)-safe literal-string escape.
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '(':
			b.WriteString(`\(`)
		case ')':
			b.WriteString(`\)`)
		default:
			switch {
			case r <= 0x7F || (r >= 0xA0 && r <= 0xFF):
				b.WriteByte(byte(r))
			case r >= 0x80 && r <= 0x9F: // raw control byte — cp1252 has
				b.WriteByte('?') // glyphs here; unmapped rune → '?'
			default:
				if v, ok := cp1252[r]; ok {
					b.WriteByte(v)
				} else {
					b.WriteByte('?')
				}
			}
		}
	}
	return b.String()
}

func pdfThreatDesc(r map[string]any) string {
	var parts []string
	seen := map[string]bool{}
	if api, ok := r["api"].(map[string]any); ok {
		if rep, ok := api["report"].(map[string]any); ok {
			if tc, ok := rep["tc_report"].([]any); ok {
				for _, e := range tc {
					entry, ok := e.(map[string]any)
					if !ok {
						continue
					}
					cls, _ := entry["classification"].(map[string]any)
					srs, _ := cls["scan_results"].([]any)
					for _, s := range srs {
						sr, ok := s.(map[string]any)
						if !ok {
							continue
						}
						eng, _ := sr["name"].(string)
						res, _ := sr["result"].(string)
						if eng != "" && res != "" {
							p := eng + ": " + res
							if !seen[p] {
								seen[p] = true
								parts = append(parts, p)
							}
						}
					}
				}
			}
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "; ")
	}
	if f, ok := r["threat_factor"].(*int64); ok && f != nil {
		return fmt.Sprintf("threat factor %d", *f)
	}
	return "-"
}

func writePDFReport(output map[string]any, path string, log *Logger) error {
	meta, _ := output["scan_metadata"].(map[string]any)
	summary, _ := output["summary"].(map[string]any)
	res := resultsList(output)

	var findings []map[string]any
	for _, r := range res {
		cls := str(r["classification"])
		if cls == "malicious" || cls == "suspicious" {
			findings = append(findings, r)
		}
	}
	order := map[string]int{"malicious": 0, "suspicious": 1}
	sort.Slice(findings, func(i, j int) bool {
		ci, cj := order[str(findings[i]["classification"])],
			order[str(findings[j]["classification"])]
		if ci != cj {
			return ci < cj
		}
		return str(findings[i]["file_path"]) < str(findings[j]["file_path"])
	})

	colHdr := fmt.Sprintf("%-64s %-26s %-26s %s",
		"FILE PATH", "FILE NAME", "THREAT", "DESCRIPTION")

	type titleLine struct {
		kind string
		text string
		rgb  [3]float64
	}
	var sb strings.Builder
	for i, k := range []string{"files_processed", "malicious", "suspicious",
		"goodware", "unknown", "quarantined", "alerts", "files_with_errors"} {
		if i > 0 {
			sb.WriteString("   ")
		}
		fmt.Fprintf(&sb, "%s: %v", strings.ReplaceAll(k, "_", " "), summary[k])
	}
	title := []titleLine{
		{"H2", "Spectra Detect Scan Report", [3]float64{0.216, 0.208, 0.278}},
		{"P", fmt.Sprintf("Host: %s   Drive: %s   Scanner v%s   Started: %s",
			str(meta["spectra_detect_host"]), str(meta["usb_drive_root"]),
			str(meta["scanner_version"]), str(meta["scan_started_at"])),
			[3]float64{0.35, 0.35, 0.35}},
		{"P", sb.String(), [3]float64{0, 0, 0}},
		{"P", "Findings shown: malicious + suspicious only — full results are " +
			"in the JSON/CSV report.", [3]float64{0.35, 0.35, 0.35}},
	}

	type row struct {
		text string
		rgb  [3]float64
	}
	var body []row
	for _, r := range findings {
		fp := str(r["file_path"])
		name := str(r["file_name"])
		if name == "" {
			if i := strings.LastIndex(fp, "/"); i >= 0 {
				name = fp[i+1:]
			} else {
				name = fp
			}
		}
		cls := str(r["classification"])
		if cls == "" {
			cls = "unavailable"
		}
		rgb, ok := pdfColors[cls]
		if !ok {
			rgb = [3]float64{0.5, 0.5, 0.5}
		}
		threat := str(r["threat_name"])
		if threat == "" {
			threat = cls
		}
		fpTrunc := fp
		if len(fpTrunc) > 64 {
			fpTrunc = fpTrunc[len(fpTrunc)-64:]
		}
		body = append(body, row{
			fmt.Sprintf("%-64s %-26s %-26s %.60s",
				fpTrunc, truncStr(name, 26), truncStr(threat, 26),
				pdfThreatDesc(r)), rgb})
	}
	if len(body) == 0 {
		body = []row{{"(no malicious or suspicious findings)",
			[3]float64{0.2, 0.5, 0.2}}}
	}

	const lineH, top, bot = 11, 555, 40
	perPage := (top - bot) / lineH
	var pages [][]row
	for i := 0; i < len(body); {
		cap := perPage
		if len(pages) == 0 {
			cap -= 10 // logo + title block on page 1
		}
		end := i + cap
		if end > len(body) {
			end = len(body)
		}
		pages = append(pages, body[i:end])
		i = end
	}

	pageStream := func(pageno int, chunk []row) []byte {
		var ops strings.Builder
		y := float64(top)
		if pageno == 0 {
			// RL template header: red wordmark left, byline
			// right-aligned (Courier 7pt = 4.2pt/char), red rule below.
			fmt.Fprintf(&ops, "BT /F2 16 Tf 0.965 0.078 0.247 rg 40 %.0f Td "+
				"(ReversingLabs) Tj ET\n", float64(top)+26)
			for _, ln := range []struct {
				dy   float64
				text string
			}{
				{10, "Generated by filescanner"},
				{0, "Open source - MIT License"},
			} {
				x := 752 - float64(len(ln.text))*4.2
				fmt.Fprintf(&ops, "BT /F1 7 Tf 0.6 0.6 0.6 rg %.1f %.1f Td "+
					"(%s) Tj ET\n", x, float64(top)+26+ln.dy, pdfEsc(ln.text))
			}
			fmt.Fprintf(&ops, "0.965 0.078 0.247 RG 1.5 w 40 %.1f m 752 %.1f l S\n",
				float64(top)+18, float64(top)+18)
			y = float64(top) + 6
			for _, tl := range title {
				size, font := 8, "F1"
				if tl.kind == "H2" {
					size, font = 14, "F2"
				}
				fmt.Fprintf(&ops, "BT /%s %d Tf %.2f %.2f %.2f rg 40 %.0f Td (%s) Tj ET\n",
					font, size, tl.rgb[0], tl.rgb[1], tl.rgb[2], y, pdfEsc(tl.text))
				if tl.kind == "H2" {
					y -= 18
				} else {
					y -= 12
				}
			}
			y -= 6
		} else {
			// slim header on continuation pages: red rule only
			fmt.Fprintf(&ops, "0.965 0.078 0.247 RG 1 w 40 %.1f m 752 %.1f l S\n",
				float64(top)+14, float64(top)+14)
		}
		fmt.Fprintf(&ops, "0.216 0.208 0.278 rg 40 %.1f 712 12 re f\n", y-3)
		fmt.Fprintf(&ops, "BT /F2 7 Tf 1 1 1 rg 42 %.0f Td (%s) Tj ET\n",
			y, pdfEsc(colHdr))
		y -= 13
		for _, rw := range chunk {
			fmt.Fprintf(&ops, "BT /F1 7 Tf %.2f %.2f %.2f rg 40 %.0f Td (%s) Tj ET\n",
				rw.rgb[0], rw.rgb[1], rw.rgb[2], y, pdfEsc(rw.text))
			y -= lineH
		}
		footer := fmt.Sprintf("Generated by filescanner (MIT License)   |   "+
			"Page %d of %d   |   generated %s",
			pageno+1, len(pages), str(meta["scan_started_at"]))
		fmt.Fprintf(&ops, "BT /F1 7 Tf 0.5 0.5 0.5 rg 40 25 Td (%s) Tj ET\n",
			pdfEsc(footer))
		return []byte(ops.String())
	}

	// 1 catalog, 2 pages, 3 Courier, 4 Helv-Bold, then per-page pairs.
	var objs []string
	kids := []int{}
	nextID := 5
	for range pages {
		kids = append(kids, nextID)
		nextID += 2
	}
	objs = append(objs, "<< /Type /Catalog /Pages 2 0 R >>")
	var kidStrs []string
	for _, k := range kids {
		kidStrs = append(kidStrs, fmt.Sprintf("%d 0 R", k))
	}
	objs = append(objs, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(kidStrs, " "), len(kids)))
	objs = append(objs,
		"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
	for pageno, chunk := range pages {
		content := pageStream(pageno, chunk)
		contID := 6 + 2*pageno
		objs = append(objs,
			fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 792 612] "+
				"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "+
				"/Contents %d 0 R >>", contID))
		objs = append(objs, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream",
			len(content), content))
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets := []int{}
	for i, body := range objs {
		offsets = append(offsets, buf.Len())
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objs)+1, xref)

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		log.Error("Failed to write pdf report: %v", err)
		return err
	}
	log.Info("Wrote PDF report: %s (%d findings, %d page%s)", path,
		len(findings), len(pages), plural(len(pages)))
	return nil
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
