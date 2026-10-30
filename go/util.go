// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// util.go — logging, counters, keyed locks, hashing, file-type detection,
// report summarization, indicator harvest, quarantine, alerting.
package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Logger: console + optional rotating file (mirrors RotatingFileHandler).
// ---------------------------------------------------------------------------

type Logger struct {
	mu      sync.Mutex
	verbose bool
	out     io.Writer // stdout
	f       *os.File  // rotating file, nil until set
	path    string
	maxB    int64
	backups int
}

func newLogger(verbose bool, logFile string, maxMB, backups int) *Logger {
	l := &Logger{verbose: verbose, out: os.Stdout}
	if logFile != "" {
		l.path = logFile
		l.maxB = int64(max(1, maxMB)) * 1024 * 1024
		l.backups = max(0, backups)
		if f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			l.f = f
		}
	}
	return l
}

func (l *Logger) maybeRotate() {
	if l.f == nil {
		return
	}
	if st, err := l.f.Stat(); err != nil || st.Size() < l.maxB {
		return
	}
	l.f.Close()
	l.f = nil
	if l.backups > 0 {
		os.Remove(fmt.Sprintf("%s.%d", l.path, l.backups))
		for i := l.backups - 1; i >= 1; i-- {
			os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
		}
		os.Rename(l.path, l.path+".1")
	} else {
		os.Remove(l.path)
	}
	l.f, _ = os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
}

func (l *Logger) log(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeRotate()
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"),
		level, fmt.Sprintf(format, args...))
	io.WriteString(l.out, line)
	if l.f != nil {
		l.f.WriteString(line)
	}
}

func (l *Logger) Info(f string, a ...any)  { l.log("INFO", f, a...) }
func (l *Logger) Warn(f string, a ...any)  { l.log("WARNING", f, a...) }
func (l *Logger) Error(f string, a ...any) { l.log("ERROR", f, a...) }
func (l *Logger) Debug(f string, a ...any) {
	if l.verbose {
		l.log("DEBUG", f, a...)
	} else if l.f != nil { // file always gets DEBUG-capable detail
		l.mu.Lock()
		l.maybeRotate()
		l.f.WriteString(fmt.Sprintf("%s [DEBUG] %s\n",
			time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(f, a...)))
		l.mu.Unlock()
	}
}
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}

// ---------------------------------------------------------------------------

type Counters struct {
	mu sync.Mutex
	c  map[string]int
}

func NewCounters() *Counters { return &Counters{c: map[string]int{}} }
func (c *Counters) Inc(key string, by int) {
	c.mu.Lock()
	c.c[key] += by
	c.mu.Unlock()
}
func (c *Counters) Snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]int{}
	for k, v := range c.c {
		out[k] = v
	}
	return out
}

type KeyedLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func NewKeyedLocks() *KeyedLocks { return &KeyedLocks{locks: map[string]*sync.Mutex{}} }
func (k *KeyedLocks) Get(key string) *sync.Mutex {
	k.mu.Lock()
	defer k.mu.Unlock()
	m := k.locks[key]
	if m == nil {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	return m
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

// readHashCapture: single streaming pass — SHA-256 the whole file while
// retaining the first captureBytes for enrichment. digestSHA1 is computed in
// the same pass only when wantSHA1 is set — FIE and cloud backends address
// samples by sha1, detect/a1000 stay sha256-only.
func readHashCapture(path string, captureBytes int, wantSHA1 bool) (digest, digestSHA1 string, head []byte, total int64) {
	f, err := openRegular(path)
	if err != nil {
		return "", "", nil, 0
	}
	defer f.Close()
	h := sha256.New()
	var h1 hash.Hash
	if wantSHA1 {
		h1 = sha1.New()
	}
	buf := make([]byte, IOChunkSize)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			h.Write(chunk)
			if h1 != nil {
				h1.Write(chunk)
			}
			total += int64(n)
			if len(head) < captureBytes {
				want := captureBytes - len(head)
				if want > n {
					want = n
				}
				head = append(head, chunk[:want]...)
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				return "", "", head, total
			}
			break
		}
	}
	if h1 != nil {
		digestSHA1 = fmt.Sprintf("%x", h1.Sum(nil))
	}
	return fmt.Sprintf("%x", h.Sum(nil)), digestSHA1, head, total
}

func humanSize(b int64) string {
	size := float64(b)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if size < 1024.0 {
			return fmt.Sprintf("%.2f %s", size, u)
		}
		size /= 1024.0
	}
	return fmt.Sprintf("%.2f PB", size)
}

func sanitizeDrivePath(d string) string {
	d = strings.TrimSpace(d)
	if len(d) == 2 && d[1] == ':' {
		d += string(os.PathSeparator)
	}
	return d
}

func shouldIncludeFile(name string, include map[string]bool) bool {
	if len(include) == 0 {
		return true
	}
	return include[strings.ToLower(filepath.Ext(name))]
}

// ---------------------------------------------------------------------------
// File walk (lazy iterator → channel)
// ---------------------------------------------------------------------------

type workItem struct{ AbsPath, RelPath string }

// iterWorkItems streams (abs, rel) pairs as the walk discovers them.
// Only regular files are enqueued (symlinks, FIFOs, sockets, devices are
// skipped); hidden dirs are pruned only when skipHidden is set.
func iterWorkItems(root string, include map[string]bool, skipHidden bool, out chan<- workItem, lg ...*Logger) {
	defer close(out)
	nonRegular := 0
	// A symlinked drive root is the user's explicit choice: walk its
	// resolved target, but emit paths under the ORIGINAL root prefix so
	// file_path matches Python (rel paths are unchanged).
	walkRoot := root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		walkRoot = r
	}
	filepath.Walk(walkRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && path != walkRoot && info.Mode().Type() != os.ModeDir {
			// Dir|Irregular: a NON-surrogate reparse directory (e.g. a OneDrive
			// placeholder folder) — never descend. Surrogates (junctions,
			// symlinks) never carry ModeDir under winsymlink and are counted
			// by the !IsRegular branch below.
			if skipDirs[info.Name()] || (skipHidden && strings.HasPrefix(info.Name(), ".")) {
				return filepath.SkipDir
			}
			nonRegular++
			if len(lg) > 0 && lg[0] != nil {
				lg[0].Debug("Skipping non-regular entry: %s", path)
			}
			return filepath.SkipDir
		}
		if info.IsDir() {
			if path != walkRoot && (skipDirs[info.Name()] ||
				(skipHidden && strings.HasPrefix(info.Name(), "."))) {
				return filepath.SkipDir
			}
			return nil
		}
		if skipFiles[info.Name()] {
			return nil
		}
		if !info.Mode().IsRegular() {
			nonRegular++
			if len(lg) > 0 && lg[0] != nil {
				lg[0].Debug("Skipping non-regular entry: %s", path)
			}
			return nil
		}
		if !shouldIncludeFile(info.Name(), include) {
			return nil
		}
		abs := path
		rel, rerr := filepath.Rel(walkRoot, path)
		if rerr != nil {
			rel = path
		} else {
			abs = filepath.Join(root, rel)
		}
		out <- workItem{abs, rel}
		return nil
	})
	if nonRegular > 0 && len(lg) > 0 && lg[0] != nil {
		lg[0].Info("Skipped %d non-regular entries (symlinks, junctions, devices, FIFOs)", nonRegular)
	}
}

// ---------------------------------------------------------------------------
// detect_file_type — magic-number classification of the head bytes.
// ---------------------------------------------------------------------------

func detectFileType(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	has := func(prefix []byte) bool {
		return len(b) >= len(prefix) && string(b[:len(prefix)]) == string(prefix)
	}
	switch {
	case has([]byte("MZ")):
		return "pe"
	case has([]byte("\x7fELF")):
		return "elf"
	case has([]byte("\xfe\xed\xfa\xce")), has([]byte("\xfe\xed\xfa\xcf")),
		has([]byte("\xce\xfa\xed\xfe")), has([]byte("\xcf\xfa\xed\xfe")):
		return "macho"
	case has([]byte("\xca\xfe\xba\xbe")):
		return "java-class"
	case has([]byte("%PDF")):
		return "pdf"
	case has([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")):
		return "ole"
	case has([]byte("PK\x03\x04")):
		return "zip"
	case has([]byte("Rar!")), has([]byte("Rar!\x1a\x07\x00")):
		return "rar"
	case has([]byte("7z\xbc\xaf\x27\x1c")):
		return "7z"
	case has([]byte("\x1f\x8b")):
		return "gzip"
	case has([]byte("BZh")):
		return "bzip2"
	case has([]byte("\xfd7zXZ\x00")):
		return "xz"
	case has([]byte("MSCF")), has([]byte("ISc(")):
		return "cab"
	case has([]byte("\xff\xd8\xff")):
		return "jpeg"
	case has([]byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case has([]byte("GIF87a")), has([]byte("GIF89a")):
		return "gif"
	case has([]byte("BM")):
		return "bmp"
	case has([]byte("II*\x00")), has([]byte("MM\x00*")):
		return "tiff"
	case has([]byte("#!")):
		return "script"
	}
	n := min(4096, len(b))
	nonprintable := 0
	for _, c := range b[:n] {
		if !(c >= 0x20 && c < 0x7f) && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\b' {
			nonprintable++
		}
	}
	if float64(nonprintable)/float64(max(1, n)) < 0.10 {
		return "text"
	}
	return "data"
}

// ---------------------------------------------------------------------------
// Classification / report summarization (same worst-entry-wins semantics)
// ---------------------------------------------------------------------------

var classificationMap = map[int]string{
	0: "unknown", 1: "goodware", 2: "suspicious", 3: "malicious",
}
var classificationStringMap = map[string]string{
	"unknown": "unknown", "no_threats_found": "goodware", "known": "goodware",
	"goodware": "goodware", "suspicious": "suspicious", "malicious": "malicious",
}

func normalizeClassification(v any) string {
	switch t := v.(type) {
	case bool:
		return "unavailable"
	case float64:
		if s, ok := classificationMap[int(t)]; ok {
			return s
		}
		return "unavailable"
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if m, ok := classificationStringMap[s]; ok {
			return m
		}
		return s
	}
	return "unavailable"
}

// summarizeReport extracts (classification, threatName, factor) taking the
// worst verdict across all tc_report entries.
func summarizeReport(report map[string]any) (cls string, threat string, factor *int64) {
	cls = "unavailable"
	tc, ok := report["tc_report"].([]any)
	if !ok {
		return
	}
	rank := map[string]int{"malicious": 4, "suspicious": 3, "goodware": 2,
		"unknown": 1, "unavailable": 0}
	best := -1
	for _, e := range tc {
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		clsObj, ok := entry["classification"].(map[string]any)
		if !ok {
			continue
		}
		var entryFactor *int64
		if fv, ok := clsObj["factor"].(float64); ok {
			i := int64(fv)
			entryFactor = &i
		}
		entryThreat, _ := clsObj["result"].(string)
		label := normalizeClassification(clsObj["classification"])
		if rank[label] > best {
			best = rank[label]
			cls = label
			if entryThreat != "" {
				threat = entryThreat
			}
			if entryFactor != nil {
				factor = entryFactor
			}
		}
		if threat == "" && entryThreat != "" {
			threat = entryThreat
		}
		if factor == nil && entryFactor != nil {
			factor = entryFactor
		}
	}
	return
}

// ---------------------------------------------------------------------------
// extract_report_indicators — bounded harvest of strings/indicators/network
// keys wherever they appear in the report tree.
// ---------------------------------------------------------------------------

var reportStringKeys = map[string]bool{"interesting_strings": true, "strings": true}
var reportIndicatorKeys = map[string]bool{"indicators": true}
var reportNetworkKeys = map[string]bool{
	"uri": true, "uris": true, "url": true, "urls": true, "domain": true,
	"domains": true, "host": true, "hosts": true, "ipv4": true, "ipv6": true,
	"ip": true, "ips": true, "requested_url": true,
}

func extractReportIndicators(report map[string]any, maxItems int) map[string]any {
	found := map[string][]any{"interesting_strings": {}, "indicators": {}, "network": {}}
	seen := map[string]map[any]bool{
		"interesting_strings": {}, "indicators": {}, "network": {},
	}
	var add func(bucket string, v any, depth int)
	add = func(bucket string, v any, depth int) {
		if depth > 4 || len(found[bucket]) >= maxItems {
			return
		}
		switch t := v.(type) {
		case string, float64, bool:
			s := fmt.Sprintf("%v", t)
			if s = strings.TrimSpace(s); s != "" && !seen[bucket][s] {
				seen[bucket][s] = true
				found[bucket] = append(found[bucket], s)
			}
		case map[string]any:
			for _, k := range []string{"description", "value", "name", "reason"} {
				if dv, ok := t[k]; ok {
					add(bucket, dv, depth+1)
					return
				}
			}
			found[bucket] = append(found[bucket], t)
		case []any:
			for i, item := range t {
				if i >= maxItems {
					break
				}
				add(bucket, item, depth+1)
			}
		}
	}
	var walk func(node any, depth int)
	walk = func(node any, depth int) {
		if depth > 12 {
			return
		}
		switch t := node.(type) {
		case map[string]any:
			for k, v := range t {
				lk := strings.ToLower(k)
				switch {
				case reportStringKeys[lk]:
					add("interesting_strings", v, 0)
				case reportIndicatorKeys[lk]:
					add("indicators", v, 0)
				case reportNetworkKeys[lk]:
					add("network", v, 0)
				}
				walk(v, depth+1)
			}
		case []any:
			for _, item := range t {
				walk(item, depth+1)
			}
		}
	}
	walk(report, 0)
	out := map[string]any{}
	for k, v := range found {
		if len(v) > 0 {
			out[k] = v
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

var unsafeNameRe = regexp.MustCompile(`[^A-Za-z0-9._\- ]`)

func quarantineFile(filePath, sha, cls, qDir, action string, log *Logger) string {
	if action == "none" {
		return ""
	}
	if li, err := os.Lstat(filePath); err != nil || !li.Mode().IsRegular() {
		log.Error("Refusing to quarantine non-regular file %s", filePath)
		return ""
	}
	if err := os.MkdirAll(qDir, 0o755); err != nil {
		log.Error("Could not create quarantine dir %s: %v", qDir, err)
		return ""
	}
	base := strings.ReplaceAll(filepath.Base(filePath), "\x00", "")
	base = unsafeNameRe.ReplaceAllString(base, "_")
	if len(base) > 150 {
		base = base[:150]
	}
	if base == "" {
		base = "file"
	}
	prefix := "nohash"
	if len(sha) >= 16 {
		prefix = sha[:16]
	}
	qAbs, _ := filepath.Abs(qDir)
	dest := filepath.Join(qAbs, prefix+"_"+base)
	// Confinement: dest must stay inside qDir.
	if rel, err := filepath.Rel(qAbs, dest); err != nil ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		log.Error("Refusing to quarantine outside %s (computed %s)", qAbs, dest)
		return ""
	}
	if _, err := os.Stat(dest); err == nil {
		if !destMatchesSource(filePath, dest) {
			log.Error("Quarantine destination %s exists but does not match source; leaving both", dest)
			return ""
		}
		if action == "move" {
			if err := os.Remove(filePath); err != nil {
				log.Error("Could not remove duplicate source %s: %v", filePath, err)
			} else {
				log.Warn("Duplicate already quarantined; removed source %s", filePath)
			}
		} else {
			log.Debug("Quarantine target already exists, skipping copy: %s", dest)
		}
		return dest
	}
	var err error
	if action == "move" {
		// Re-verify via openRegular (O_NOFOLLOW + fstat) right before the
		// move: refuse a symlink/non-regular swapped in since the lstat
		// above. A failed recheck fails the whole move — no copy fallback
		// on a suspect source.
		var rv *os.File
		if rv, err = openRegular(filePath); err == nil {
			var st os.FileInfo
			st, err = rv.Stat()
			rv.Close()
			if err == nil {
				if err = os.Rename(filePath, dest); err != nil {
					err = copyThenRemove(filePath, dest)
				} else {
					// Rename preserves the full source mode, incl.
					// setuid/setgid/sticky — strip the privileged
					// bits (the copy path's 0o666 mask never lets
					// them through). The bits are absent on
					// Windows, so this is a no-op there.
					err = os.Chmod(dest, st.Mode()&^(os.ModeSetuid|os.ModeSetgid|os.ModeSticky))
				}
			}
		}
	} else {
		err = copyFile(filePath, dest)
	}
	if err != nil {
		log.Error("Quarantine %s failed for %s: %v", action, filePath, err)
		return ""
	}
	log.Warn("Quarantined (%s) %s -> %s [%s]", action, filePath, dest, cls)
	return dest
}

// destMatchesSource reports whether dest is a regular file (lstat) whose size
// equals the source's (fstat on a verified fd). A truncated leftover is not a
// duplicate.
func destMatchesSource(src, dest string) bool {
	in, err := openRegular(src)
	if err != nil {
		return false
	}
	defer in.Close()
	sst, err := in.Stat()
	if err != nil {
		return false
	}
	dst, err := os.Lstat(dest)
	return err == nil && dst.Mode().IsRegular() && dst.Size() == sst.Size()
}

// errNotRegular: openRegular refused a non-regular file or symlink.
var errNotRegular = errors.New("not a regular file")

// openRegular opens a scanned file for reading only if it is a regular file
// and not a symlink (closes the walk->open TOCTOU window: a file swapped for
// a symlink/FIFO/device after the walk is refused). Used for hashing, every
// backend upload body, the read-speed gate and the quarantine source.
func openRegular(path string) (*os.File, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	return f, nil
}

// copyStream is io.Copy; a variable so tests can inject a failing copy.
var copyStream = io.Copy

// copyFile copies src to a NEW dst (O_EXCL) through a verified regular fd.
// Mode comes from that fd, masked to 0o666 and the umask (no setuid/setgid/sticky/exec),
// and atime/mtime are preserved (parity with Python _copy_verified). A failed
// copy removes the partial dst; a dst that already exists is never touched.
func copyFile(src, dst string) error {
	in, err := openRegular(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	// Capture atime before the copy reads src — the read would bump it
	// (matters where it is fetched live, e.g. GetFileTime on Windows).
	at := accessTime(in, st)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		st.Mode().Perm()&0o666)
	if err != nil {
		return err
	}
	_, err = copyStream(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return err
	}
	os.Chtimes(dst, at, st.ModTime()) // best-effort
	return nil
}
func copyThenRemove(src, dst string) error {
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

// ---------------------------------------------------------------------------
// Alerter — file / webhook / syslog. (Windows Event Log is Python-only.)
// ---------------------------------------------------------------------------

type Alerter struct {
	AlertOn      map[string]bool
	AlertsFile   string
	WebhookURL   string
	SyslogAddr   *net.UDPAddr
	eventlogSend func(cls, msg string) // nil when channel disabled
	log          *Logger
	mu           sync.Mutex
	hc           *http.Client
}

var syslogSeverity = map[string]int{"malicious": 2, "suspicious": 4}

func NewAlerter(alertOn map[string]bool, alertsFile, webhook string,
	syslogAddr *net.UDPAddr, eventlog bool, log *Logger) *Alerter {
	a := &Alerter{AlertOn: alertOn, AlertsFile: alertsFile, WebhookURL: webhook,
		SyslogAddr: syslogAddr, log: log,
		// Never follow redirects: a 3xx would re-POST the alert payload to a
		// foreign host (same guard every other client in this package pins).
		hc: &http.Client{Timeout: 10 * time.Second,
			CheckRedirect: checkNoRedirect}}
	if eventlog {
		a.eventlogSend = setupEventLog(log) // build-tagged: real on Windows
	}
	return a
}

func (a *Alerter) MaybeAlert(record map[string]any) bool {
	cls, _ := record["classification"].(string)
	if !a.AlertOn[cls] {
		return false
	}
	payload := map[string]any{
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"scanner_version": ScriptVersion,
		"classification":  cls,
		"threat_name":     record["threat_name"],
		"file_path":       record["file_path"],
		"absolute_path":   record["absolute_path"],
		"sha256":          record["sha256"],
		"file_type":       record["file_type"],
		"quarantined_to":  record["quarantined_to"],
	}
	a.toFile(payload)
	a.toWebhook(payload)
	a.toSyslog(payload)
	if a.eventlogSend != nil {
		data, _ := json.Marshal(payload)
		a.eventlogSend(cls, string(data))
	}
	return true
}

func (a *Alerter) toFile(payload map[string]any) {
	if a.AlertsFile == "" {
		return
	}
	data, _ := json.Marshal(payload)
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.AlertsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		a.log.Error("Could not write alert to %s: %v", a.AlertsFile, err)
		return
	}
	defer f.Close()
	f.Write(append(data, '\n'))
}

func (a *Alerter) toWebhook(payload map[string]any) {
	if a.WebhookURL == "" {
		return
	}
	data, _ := json.Marshal(payload)
	resp, err := a.hc.Post(a.WebhookURL, "application/json",
		strings.NewReader(string(data)))
	if err != nil {
		a.log.Error("Webhook alert failed: %v", err)
		return
	}
	resp.Body.Close()
	// With redirects un-followed a 3xx lands here — treat it as a failure
	// (parity with the Python HTTPError path), same as any other non-2xx.
	if resp.StatusCode >= 300 {
		a.log.Error("Webhook alert failed: HTTP %d", resp.StatusCode)
	}
}

func (a *Alerter) toSyslog(payload map[string]any) {
	if a.SyslogAddr == nil {
		return
	}
	sev := 5
	if s, ok := syslogSeverity[fmt.Sprintf("%v", payload["classification"])]; ok {
		sev = s
	}
	pri := 13*8 + sev
	threat, _ := payload["threat_name"].(string)
	msg := fmt.Sprintf("<%d>SpectraDetectScanner: %s %s sha256=%v path=%v",
		pri, strings.ToUpper(fmt.Sprintf("%v", payload["classification"])),
		threat, payload["sha256"], payload["file_path"])
	conn, err := net.DialUDP("udp", nil, a.SyslogAddr)
	if err != nil {
		a.log.Error("Syslog alert failed: %v", err)
		return
	}
	defer conn.Close()
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	conn.Write([]byte(msg))
}

// ---------------------------------------------------------------------------
// ResultsWriter — append-only NDJSON sink.
// ---------------------------------------------------------------------------

type ResultsWriter struct {
	mu sync.Mutex
	f  *os.File
}

func NewResultsWriter(path string) (*ResultsWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &ResultsWriter{f: f}, nil
}
func (w *ResultsWriter) Write(rec map[string]any) {
	data, _ := json.Marshal(rec)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.f.Write(append(data, '\n'))
}
func (w *ResultsWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.f.Close()
}

// ---------------------------------------------------------------------------
// sortedSet helper for metadata/log lines
// ---------------------------------------------------------------------------

func sortedKeys(s map[string]bool) []string {
	out := setKeys(s)
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Upload timeouts — Python requests timeout=(30, N) semantics: 30s connect,
// then N seconds of *inactivity* per I/O, never a whole-request deadline (a
// large upload that keeps progressing must succeed however long it takes).
// ---------------------------------------------------------------------------

const uploadConnectTimeout = 30 * time.Second

// errUploadStalled is the cancel cause when an upload makes no progress for
// its read timeout (requests' ReadTimeout).
var errUploadStalled = errors.New("read timeout")

// applyUploadTimeouts sets the transport-level bounds: dial + TLS handshake
// 30s, and readTimeout to wait for response headers once the body is sent.
func applyUploadTimeouts(tr *http.Transport, readTimeout time.Duration) {
	tr.DialContext = (&net.Dialer{Timeout: uploadConnectTimeout,
		KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = uploadConnectTimeout
	tr.ResponseHeaderTimeout = readTimeout
}

// idleGuard cancels its context when no Read progress happens for idle.
// The timer (not a check inside Read) is what fires: a stalled peer blocks
// the transport's conn write, so Read is simply never called again.
type idleGuard struct {
	idle time.Duration
	t    *time.Timer
}

// newIdleGuard returns the request context, the guard, and a release func
// the caller must defer.
func newIdleGuard(idle time.Duration) (context.Context, *idleGuard, func()) {
	ctx, cancel := context.WithCancelCause(context.Background())
	g := &idleGuard{idle: idle}
	g.t = time.AfterFunc(idle, func() {
		cancel(fmt.Errorf("%w: no upload progress for %s",
			errUploadStalled, idle))
	})
	// Armed by the first body Read: dial/TLS (30s bounds) and any client-side
	// pacing before the request starts don't count as upload inactivity.
	g.t.Stop()
	return ctx, g, func() { g.t.Stop(); cancel(context.Canceled) }
}

func (g *idleGuard) touch() { g.t.Reset(g.idle) }

// body wraps the request body: each successful Read re-arms the window; EOF
// disarms it (ResponseHeaderTimeout governs the wait for the answer). Close
// is delegated so an io.Pipe writer goroutine is released.
func (g *idleGuard) body(r io.Reader) io.ReadCloser {
	return &guardedReader{r: r, g: g, stopOnEOF: true}
}

// readResponse re-arms the window and reads up to limit bytes of resp.Body
// with the same per-Read inactivity bound.
func (g *idleGuard) readResponse(rc io.Reader, limit int64) []byte {
	g.touch()
	b, _ := io.ReadAll(&guardedReader{r: io.LimitReader(rc, limit), g: g})
	return b
}

// err maps a transport error to the stall cause when the guard fired.
func (g *idleGuard) err(ctx context.Context, e error) error {
	if c := context.Cause(ctx); c != nil && errors.Is(c, errUploadStalled) {
		return c
	}
	return e
}

type guardedReader struct {
	r         io.Reader
	g         *idleGuard
	stopOnEOF bool
}

func (gr *guardedReader) Read(p []byte) (int, error) {
	n, err := gr.r.Read(p)
	if n > 0 {
		gr.g.touch()
	}
	if err == io.EOF && gr.stopOnEOF {
		gr.g.t.Stop()
	}
	return n, err
}

func (gr *guardedReader) Close() error {
	if c, ok := gr.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
