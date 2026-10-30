// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestQuarantinePartialCopyRemoved(t *testing.T) {
	for _, action := range []string{"copy", "move"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "s.bin")
			os.WriteFile(src, []byte("payload"), 0o644)
			orig := copyStream
			copyStream = func(w io.Writer, r io.Reader) (int64, error) {
				n, _ := w.Write([]byte("part"))
				return int64(n), errors.New("no space left on device")
			}
			defer func() { copyStream = orig }()
			q := filepath.Join(dir, "q")
			mv := filepath.Join(dir, "mv.bin")
			var got string
			if action == "copy" {
				got = quarantineFile(src, "abcdef0123456789ab", "m", q, "copy", newLogger(false, "", 0, 0))
			} else {
				// move falls back to copyThenRemove when rename fails.
				err := copyThenRemove(src, mv)
				if err == nil {
					t.Fatal("expected copy failure")
				}
			}
			if got != "" {
				t.Fatalf("got %q, want empty", got)
			}
			if b, err := os.ReadFile(src); err != nil || string(b) != "payload" {
				t.Fatalf("source damaged: %v %q", err, b)
			}
			if ents, _ := os.ReadDir(q); len(ents) != 0 {
				t.Fatalf("partial dest left: %v", ents)
			}
			if _, err := os.Stat(mv); err == nil {
				t.Fatal("partial move dest left")
			}
		})
	}
}

func TestCopyFileNeverRemovesPreexistingDest(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "s.bin")
	dst := filepath.Join(dir, "d.bin")
	os.WriteFile(src, []byte("new"), 0o644)
	os.WriteFile(dst, []byte("old"), 0o644)
	if err := copyFile(src, dst); err == nil {
		t.Fatal("expected O_EXCL failure")
	}
	if b, _ := os.ReadFile(dst); string(b) != "old" {
		t.Fatalf("pre-existing dest touched: %q", b)
	}
}

func TestQuarantineCopyStripsSetuidAndExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	for _, action := range []string{"copy", "move"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "s.bin")
			os.WriteFile(src, []byte("payload"), 0o644)
			if err := os.Chmod(src, 0o755|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "d.bin")
			var err error
			if action == "copy" {
				err = copyFile(src, dst)
			} else {
				err = copyThenRemove(src, dst)
			}
			if err != nil {
				t.Fatal(err)
			}
			fi, _ := os.Stat(dst)
			if m := fi.Mode(); m&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
				m.Perm()&0o111 != 0 || m.Perm()&^0o644 != 0 {
				t.Fatalf("mode %v: want no suid/sgid/sticky/exec and within 0644", m)
			}
		})
	}
}

func TestQuarantineMoveRenameStripsSetuid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("setuid semantics differ as root")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "s.bin")
	os.WriteFile(src, []byte("payload"), 0o644)
	if err := os.Chmod(src, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	q := filepath.Join(dir, "q")
	// Same-dir quarantine: the os.Rename fast path must strip the
	// privileged bits from the moved dest (it keeps owner perms,
	// incl. exec).
	got := quarantineFile(src, "abcdef0123456789ab", "m", q, "move",
		newLogger(false, "", 0, 0))
	if got == "" {
		t.Fatal("quarantine move refused")
	}
	fi, err := os.Stat(got)
	if err != nil {
		t.Fatal(err)
	}
	if m := fi.Mode(); m&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		m.Perm() != 0o755 {
		t.Fatalf("mode %v: want 0755 with no suid/sgid/sticky", m)
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Fatal("source should be moved")
	}
}

func TestCopyFileCloseFailureRemovesDst(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "s.bin")
	dst := filepath.Join(dir, "d.bin")
	os.WriteFile(src, []byte("payload"), 0o644)
	orig := copyStream
	copyStream = func(w io.Writer, r io.Reader) (int64, error) {
		w.Write([]byte("part"))
		w.(*os.File).Close() // final close then fails with ErrClosed
		return 4, nil
	}
	defer func() { copyStream = orig }()
	if err := copyFile(src, dst); err == nil {
		t.Fatal("expected close failure")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("partial dst left")
	}
	if b, _ := os.ReadFile(src); string(b) != "payload" {
		t.Fatalf("source damaged: %q", b)
	}
}

func TestQuarantinePreservesAtimeAndMtime(t *testing.T) {
	for _, action := range []string{"copy", "move"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "s.bin")
			os.WriteFile(src, []byte("payload"), 0o644)
			// Distinct atime/mtime: equal values would mask an atime
			// regression (the old atime:=mtime behaviour passed).
			at := time.Unix(1_400_000_000, 0)
			mt := time.Unix(1_500_000_000, 0)
			os.Chtimes(src, at, mt)
			dst := filepath.Join(dir, "d.bin")
			var err error
			if action == "copy" {
				err = copyFile(src, dst)
			} else {
				err = copyThenRemove(src, dst)
			}
			if err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(dst)
			if err != nil {
				t.Fatal(err)
			}
			fi, err := f.Stat()
			gotAt := accessTime(f, fi) // needs the live fd on Windows
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
			if d := fi.ModTime().Sub(mt); d > time.Second || d < -time.Second {
				t.Fatalf("mtime %v want %v", fi.ModTime(), mt)
			}
			if d := gotAt.Sub(at); d > time.Second || d < -time.Second {
				t.Fatalf("atime %v want %v", gotAt, at)
			}
		})
	}
}

func TestQuarantineLeftoverDestSafety(t *testing.T) {
	log := newLogger(false, "", 0, 0)
	sha := "abcdef0123456789ab"
	setup := func(leftover string) (src, q, left string) {
		dir := t.TempDir()
		src = filepath.Join(dir, "s.bin")
		os.WriteFile(src, []byte("payload"), 0o644)
		q = filepath.Join(dir, "q")
		os.MkdirAll(q, 0o755)
		left = filepath.Join(q, sha[:16]+"_s.bin")
		os.WriteFile(left, []byte(leftover), 0o644)
		return
	}
	t.Run("truncated", func(t *testing.T) {
		for _, action := range []string{"move", "copy"} {
			src, q, left := setup("pay")
			if got := quarantineFile(src, sha, "m", q, action, log); got != "" {
				t.Fatalf("%s: reported %q", action, got)
			}
			if b, _ := os.ReadFile(src); string(b) != "payload" {
				t.Fatalf("%s: source lost", action)
			}
			if b, _ := os.ReadFile(left); string(b) != "pay" {
				t.Fatalf("%s: dest touched", action)
			}
		}
	})
	t.Run("equal-size-move", func(t *testing.T) {
		src, q, _ := setup("payload")
		if got := quarantineFile(src, sha, "m", q, "move", log); got == "" {
			t.Fatal("duplicate should be reported")
		}
		if _, err := os.Stat(src); err == nil {
			t.Fatal("source should be removed")
		}
	})
}

func TestQuarantineMoveReverifiesSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("chmod 000 stays readable as root")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "s.bin")
	os.WriteFile(src, []byte("payload"), 0o644)
	if err := os.Chmod(src, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(src, 0o644)
	q := filepath.Join(dir, "q")
	// The lstat still sees a regular file, but the re-verify open fails, so
	// the move must be refused: without the recheck the rename would still
	// succeed (it needs only directory write permission).
	if got := quarantineFile(src, "abcdef0123456789ab", "m", q, "move",
		newLogger(false, "", 0, 0)); got != "" {
		t.Fatalf("got %q, want refusal", got)
	}
	if _, err := os.Lstat(src); err != nil {
		t.Fatalf("source lost: %v", err)
	}
	if ents, _ := os.ReadDir(q); len(ents) != 0 {
		t.Fatalf("dest created: %v", ents)
	}
}
