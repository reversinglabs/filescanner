// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build unix

package main

import "syscall"

func mkfifo(path string) error { return syscall.Mkfifo(path, 0o644) }
