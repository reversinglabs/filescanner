#!/usr/bin/env bash
# Copyright (c) 2026 ReversingLabs
# SPDX-License-Identifier: MIT

# Live e2e test runner — maps credentials from the known .env files into the
# FILESCANNER_E2E_* variables tests/test_e2e_live.py consumes.
#
# Usage:  ./tests/e2e_live.sh [pytest args...]
#         ./tests/e2e_live.sh -k fie -v          # only FIE tests
#         ./tests/e2e_live.sh tests/test_e2e_live.py::test_e2e_detect -v
#
# Sources dotenv-style credential files (whichever exist). Default: ~/.env.
# Override with FILESCANNER_ENV_FILES (colon-separated paths). Recognized
# vars: SPECTRA_TOKEN, TISCALE_WORKER_* (detect), DUT_HOST/DUT_API_TOKEN
# (a1000), RL_USERNAME/RL_PASSWORD/RL_HOST or TICLOUD_* (ticloud).
# FIE: a container must already be running (see tests/e2e_fie_up.sh).

set -euo pipefail
cd "$(dirname "$0")/.."

IFS=':' read -ra env_files <<< "${FILESCANNER_ENV_FILES:-$HOME/.env}"
for f in "${env_files[@]}"; do
    [ -f "$f" ] && { set -a; source "$f"; set +a; }
done

export FILESCANNER_E2E=1

# detect (tiscale worker): API prefix has an empty token in tokenauth_acl on
# this worker — any value authenticates. Point at the worker host.
: "${FILESCANNER_E2E_DETECT_HOST:=https://${TISCALE_WORKER_IP:-${TISCALE_WORKER_HOST:-}}}"
: "${FILESCANNER_E2E_DETECT_TOKEN:=${SPECTRA_TOKEN:-e2e-placeholder}}"
export FILESCANNER_E2E_DETECT_HOST FILESCANNER_E2E_DETECT_TOKEN

# a1000: prefer DUT_HOST + DUT_API_TOKEN.
: "${FILESCANNER_E2E_A1000_HOST:=https://${DUT_HOST:-}}"
: "${FILESCANNER_E2E_A1000_TOKEN:=${DUT_API_TOKEN:-}}"
export FILESCANNER_E2E_A1000_HOST FILESCANNER_E2E_A1000_TOKEN

# fie: local container started by tests/e2e_fie_up.sh
: "${FILESCANNER_E2E_FIE_HOST:=http://localhost:8088}"
export FILESCANNER_E2E_FIE_HOST

# ticloud
: "${FILESCANNER_E2E_TICLOUD_HOST:=${RL_HOST:-https://ticloud01.reversinglabs.com}}"
: "${FILESCANNER_E2E_TICLOUD_USER:=${RL_USERNAME:-${TICLOUD_USER:-}}}"
: "${FILESCANNER_E2E_TICLOUD_PASS:=${RL_PASSWORD:-${TICLOUD_TOKEN:-}}}"
export FILESCANNER_E2E_TICLOUD_HOST FILESCANNER_E2E_TICLOUD_USER FILESCANNER_E2E_TICLOUD_PASS

# prebuild the go binary once so the module fixture doesn't compile per run
go build -o /tmp/filescanner-e2e ./go/ 2>/dev/null || true

exec python3 -m pytest tests/test_e2e_live.py "$@"
