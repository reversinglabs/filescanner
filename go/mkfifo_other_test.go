// Copyright (c) 2026 ReversingLabs
// SPDX-License-Identifier: MIT

//go:build !unix

package main

import "errors"

func mkfifo(string) error { return errors.New("mkfifo unsupported") }
