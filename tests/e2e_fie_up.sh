#!/usr/bin/env bash
# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

# Start a local FIE container for e2e testing.
#
# Requires: docker login registry.reversinglabs.com (cloud username/password),
# an RL license file, and enough VM resources (cores get OOM-killed under 4 GiB
# — Colima start with e.g. --cpu 8 --memory 12).
#
# RL_WITHOUT_MALICIOUS_THREAT_DATA=true skips the ~20 GiB threat-DB download:
# /scan still runs real Spectra Core static analysis, and /check-sample
# returns the ambiguous-OK miss — which is exactly what hash_then_scan is
# designed to fall through on.
#
# Usage: ./tests/e2e_fie_up.sh [/path/to/rl-license.lic]
#        ./tests/e2e_fie_up.sh down

set -euo pipefail

NAME=fie-e2e
IMAGE=registry.reversinglabs.com/fie/file-inspection-engine:latest
PORT=${FILESCANNER_E2E_FIE_PORT:-8088}
LIC=${1:-}
if [ -z "$LIC" ]; then
    LIC=$(ls -t "$HOME"/RL_*.lic 2>/dev/null | head -1 || true)
fi

if [ "${1:-}" = "down" ]; then
    docker rm -f "$NAME" 2>/dev/null || true
    exit 0
fi

if [ ! -f "$LIC" ]; then
    echo "license file not found: $LIC" >&2
    echo "pass the path explicitly: $0 /path/to/rl-license.lic" >&2
    exit 2
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker pull --platform linux/amd64 "$IMAGE"

# GOMAXPROCS=1 + single core: amd64-under-emulation Go binaries crash with
# "sync: inconsistent mutex state" under SMP contention (QEMU/Rosetta both
# affected). Serializing the scheduler avoids it; plenty fast for e2e files.
docker run -d --name "$NAME" --platform linux/amd64 \
    -e RL_LICENSE="$(cat "$LIC")" \
    -e RL_WITHOUT_MALICIOUS_THREAT_DATA=true \
    -e GOMAXPROCS=1 \
    -e RL_NUMBER_OF_REGULAR_CORES=1 \
    -e RL_NUMBER_OF_LARGE_CORES=0 \
    -p "${PORT}:8000" "$IMAGE" >/dev/null

echo "waiting for FIE readiness on :$PORT ..."
for i in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${PORT}/readyz" || true)
    [ "$code" = "200" ] && { echo "FIE ready (http://localhost:${PORT})"; exit 0; }
    sleep 2
done
echo "FIE did not become ready in 180s; last /readyz=$code" >&2
docker logs "$NAME" 2>&1 | tail -15 >&2
exit 1
