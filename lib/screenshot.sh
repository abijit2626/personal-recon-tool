# shellcheck shell=bash
# shellcheck source=../ghost.sh

# =============================================================================
# screenshot.sh — web screenshotting (gowitness / aquatone)
# =============================================================================

screenshot_web_targets() {
    local url_list_file="$1"
    local dir="$OUTDIR/screenshots"; mkdir -p "$dir"
    section "Web Screenshotting"

    if check_tool gowitness "go install github.com/sensepost/gowitness"; then
        log_info "Running gowitness..."
        gowitness file -f "$url_list_file" -P "$dir" --no-http-connectivity-check &>"$dir/gowitness.log"
        log_success "Screenshots -> $dir/"
    elif check_tool aquatone "apt install aquatone"; then
        log_info "Running aquatone..."
        aquatone -out "$dir" <"$url_list_file" &>"$dir/aquatone.log"
        log_success "Screenshots -> $dir/"
    else
        log_warn "No screenshot tool found (gowitness/aquatone) — skipping visual recon."
    fi
}
