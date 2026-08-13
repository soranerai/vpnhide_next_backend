#!/usr/bin/env bash
set -euo pipefail
PERF_BACKEND=kpatch exec "$(cd "$(dirname "$0")/../.." && pwd)/kmod/test/run-perf.sh" "$@"
