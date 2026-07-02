# shellcheck shell=bash
# =============================================================================
# core.sh — shared utilities for recon.sh
# =============================================================================

# Section header for terminal output (global fallback;
# overridden inside run_scan() to also write to report.txt).
section() { echo -e "\n${CYAN}==== $* ====${NC}\n"; }

# =============================================================================
# GUARD CLAUSE: tool availability check
# Every optional-tool function calls this first and returns early (not exit)
# so one missing tool never kills the whole run.
# =============================================================================
check_tool() {
    local tool="$1"
    local hint="${2:-}"
    if ! command -v "$tool" &>/dev/null; then
        log_warn "'$tool' not found, skipping this check.${hint:+ ($hint)}"
        return 1
    fi
    return 0
}

# Run a command with a hard timeout so one hung tool doesn't stall the scan.
# Usage: run_capped <seconds> <outfile> -- cmd args...
run_capped() {
    local secs="$1" outfile="$2"; shift 2
    [[ "$1" == "--" ]] && shift
    timeout "${secs}s" "$@" >"$outfile" 2>&1
    local rc=$?
    if [[ $rc -eq 124 ]]; then
        log_warn "$(basename "$1") timed out after ${secs}s, results may be partial."
    fi
    return $rc
}
