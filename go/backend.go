// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

// backend.go — ScanBackend contract, SubmitOutcome, PollRef, and the
// makeBackend factory. Mirrors the backend section of filescanner.py.
package main

import (
	"fmt"
	"strings"
	"time"
)

// SubmitOutcome is one submit attempt's result.
//
//	Kind "receipt" — accepted for async processing; Ref is the backend-specific
//	                 receipt (detect: task_url) stored in ScanDB.task_url.
//	Kind "verdict" — synchronous verdict on submit (FIE); verdict fields set.
//	Kind "error"   — submission failed; HTTPStatus/Error say why.
type SubmitOutcome struct {
	Kind           string
	Ref            string
	HTTPStatus     *int
	Error          *string
	Classification *string
	ThreatName     *string
	ThreatFactor   *int64
	ReportJSON     *string
}

// PollRef is one receipt to poll: Ref is the backend receipt (detect:
// task_url); Sha256 rides along for backends that poll by hash.
type PollRef struct {
	Ref    string
	Sha256 string
}

// ScanBackend is the contract every scan backend implements; the pipeline
// only sees this interface. PollBatch maps each ref -> "pending" | "gone" |
// verdict map{classification,threat_name,threat_factor,report_json}; "gone"
// is terminal (receipt purged server-side), transient poll errors map to
// "pending" so the caller unclaims and retries.
type ScanBackend interface {
	Name() string
	NeedsSHA1() bool
	IsSync() bool // verdict on submit (FIE) — PollBatch unused
	Probe(timeout time.Duration) bool
	WaitReady(maxWait, interval time.Duration, log *Logger) bool
	AvailableNow(ttl time.Duration) bool
	MarkUnavailable()
	SubmitOnce(filePath, sha256, sha1 string, meta map[string]any) SubmitOutcome
	SubmitWithBackoff(filePath, sha256, sha1 string, meta map[string]any,
		a *Args, log *Logger) SubmitOutcome
	PollBatch(refs []PollRef) map[string]any
}

func strOrNil(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
func intOrNil(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

// backendFactories: name -> factory(*Args) -> ScanBackend. The a1000/cloud
// backend beads register their factories here; factories for auth-bearing
// backends must probe once and fail fast on 401/403 (detect needs no auth
// probe — WaitReady in runScan is its reachability gate; fie is likewise
// unauthenticated and gated by WaitReady).
var backendFactories = map[string]func(a *Args) (ScanBackend, error){
	"detect": func(a *Args) (ScanBackend, error) {
		return NewDetectBackend(NewDetectAsyncClient(
			a.Host, a.Token, !a.NoVerifySSL, a.Proxy)), nil
	},
	"fie": func(a *Args) (ScanBackend, error) {
		host := strings.TrimSpace(a.FieHost)
		if host == "" {
			return nil, fmt.Errorf(
				"fie.host is required when scan.backend='fie'")
		}
		return NewFieBackend(NewFieClient(host, !a.NoVerifySSL, a.Proxy),
			a.FieMode, a.FieTrustOK, a.FieExternalID), nil
	},
	"a1000": func(a *Args) (ScanBackend, error) {
		host := strings.TrimSpace(a.A1000Host)
		if host == "" {
			return nil, fmt.Errorf(
				"a1000.host is required when scan.backend='a1000'")
		}
		token := strings.TrimSpace(a.A1000Token)
		if token == "" {
			return nil, fmt.Errorf(
				"a1000.token is required when scan.backend='a1000'")
		}
		c := NewA1000Client(host, token, !a.NoVerifySSL, a.Proxy)
		// One auth check at startup: 401/403 means the token is wrong and
		// every request would fail — fail fast. Unreachable or 5xx is NOT
		// fatal here: WaitReady in runScan is the reachability gate (same
		// shape as detect/fie).
		if st, ok := c.probeStatus(8 * time.Second); ok &&
			(st == 401 || st == 403) {
			return nil, fmt.Errorf("a1000 rejected the configured token "+
				"(HTTP %d) — check a1000.token", st)
		}
		fields := map[string]string{}
		if v := strings.TrimSpace(a.A1000Analysis); v != "" {
			fields["analysis"] = v
		}
		if v := strings.TrimSpace(a.A1000Tags); v != "" {
			fields["tags"] = v
		}
		if v := strings.TrimSpace(a.A1000Comment); v != "" {
			fields["comment"] = v
		}
		if v := strings.TrimSpace(a.A1000ArchivePassword); v != "" {
			fields["archive_password"] = v
		}
		if v := strings.TrimSpace(a.A1000SandboxPlatform); v != "" {
			fields["rl_cloud_sandbox_platform"] = v
		}
		return NewA1000Backend(c, fields, a.A1000ReportDetail), nil
	},
	"cloud": func(a *Args) (ScanBackend, error) {
		host := strings.TrimSpace(a.TicloudHost)
		if host == "" {
			return nil, fmt.Errorf(
				"ticloud.host is required when scan.backend='cloud'")
		}
		user := strings.TrimSpace(a.TicloudUsername)
		pass := strings.TrimSpace(a.TicloudPassword)
		if user == "" || pass == "" {
			return nil, fmt.Errorf("ticloud.username and " +
				"ticloud.password are required when scan.backend='cloud'")
		}
		c := NewTicloudClient(host, user, pass, !a.NoVerifySSL, a.Proxy,
			time.Duration(a.TicloudUploadTimeout)*time.Second,
			time.Duration(a.TicloudMinIntervalMs)*time.Millisecond,
			a.TicloudExtended)
		// One auth check at startup (same shape as a1000): 401/403 means
		// the credentials are wrong and every request would fail — fail
		// fast. Unreachable or 5xx is NOT fatal here: WaitReady in
		// runScan is the reachability gate.
		if st, ok := c.probeStatus(8 * time.Second); ok &&
			ticloudAuthStatuses[st] {
			return nil, fmt.Errorf("ticloud rejected the configured "+
				"credentials (HTTP %d) — check ticloud.username/"+
				"ticloud.password", st)
		}
		return NewCloudBackend(c, a.TicloudDomain,
			a.TicloudArchivePassword), nil
	},
}

var validBackends = map[string]bool{
	"detect": true, "a1000": true, "fie": true, "cloud": true,
}

// makeBackend constructs the ScanBackend selected by a.Backend; error on an
// unknown value or a backend whose adapter is not registered yet (caller
// exits with code 2, matching loadConfig/normalizeArgs failures).
func makeBackend(a *Args) (ScanBackend, error) {
	name := a.Backend
	if !validBackends[name] {
		return nil, fmt.Errorf("scan.backend=%q invalid; valid: "+
			"detect|a1000|fie|cloud", name)
	}
	f := backendFactories[name]
	if f == nil {
		return nil, fmt.Errorf("backend %q is not yet supported in this build",
			name)
	}
	return f(a)
}
