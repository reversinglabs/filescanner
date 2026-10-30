// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"database/sql"
	"sync"
	"testing"
)

// processed() maps a tiscale task body's "processed" field to 0/1. Python
// treats `task.get("processed") in (None, 0)` -> still running; Go must
// match — JSON false must NOT mean done (False == 0 in Python), while any
// non-numeric truthy value means done in both impls.
func TestProcessedBool(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want float64
	}{
		{false, 0}, // explicit false = still running (False == 0 in py)
		{true, 1},  // explicit true = done
		{nil, 0},   // missing key = still running
		{float64(0), 0},
		{float64(1), 1},
		{float64(2), 2}, // numeric passthrough — truthy != 0 to callers
		{"1", 1},        // non-numeric truthy -> done, same as Python
		{"0", 1},        // "0" != 0 in Python too -> done
		{"x", 1},
	} {
		if got := processed(map[string]any{"processed": tc.v}); got != tc.want {
			t.Fatalf("processed(%v): got %v want %v", tc.v, got, tc.want)
		}
	}
}

// A saturated precheckQ fails open: the non-blocking send falls through to
// inline submit instead of blocking under the keyed lock.
func TestUploadWorkerPrecheckFullBypasses(t *testing.T) {
	_, det := detectTestServer(t, `{"processed":0}`, 200)
	f := writeFile(t, "b.bin", "MZ-b")
	sha := fileSHA256(t, f)

	db := newIntegrationDB(t)
	defer db.Close()
	ctx := integrationCtx(t, integrationArgs())

	pq := make(chan precheckItem, 1)
	pq <- precheckTestItem(pcSHA256a, "fill.bin") // saturate the stage
	wq := make(chan precheckItem, 1)
	wq <- precheckItem{AbsPath: f, RelPath: "b.bin", Raw: true}
	close(wq)
	var feedWG sync.WaitGroup
	feedWG.Add(1)
	writer, _ := newIntegrationWriter(t)
	uploadWorker(ctx, db, det, wq, pq, &feedWG, writer)
	writer.Close()

	if got := ctx.Counters.Snapshot()["precheck_bypassed"]; got != 1 {
		t.Fatalf("precheck_bypassed=%d, want 1", got)
	}
	rows := db.qAll("SELECT task_url FROM uploads WHERE sha256=?", sha)
	if rows == nil {
		t.Fatal("select failed")
	}
	defer rows.Close()
	var tu sql.NullString
	if !rows.Next() || rows.Scan(&tu) != nil || !tu.Valid {
		t.Fatalf("want submitted row with receipt for %s", sha)
	}
}
