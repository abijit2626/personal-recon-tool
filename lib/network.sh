# shellcheck shell=bash
# shellcheck source=../ghost.sh

# =============================================================================
# network.sh — advanced nmap phases (UDP, NSE vuln, TLS)
# =============================================================================

nmap_udp_scan() {
    local target="$1"
    local dir="$OUTDIR/nmap"; mkdir -p "$dir"
    section "UDP Scan (top 50)"
    check_tool nmap || return 1
    log_info "This needs root — running via sudo if not already root."
    local runner=(nmap)
    [[ $EUID -ne 0 ]] && runner=(sudo nmap)
    "${runner[@]}" -sU --top-ports 50 -oA "$dir/udp_top50" -oG "$dir/udp_top50.gnmap" "$target" &>/dev/null
    log_success "UDP scan -> $dir/udp_top50.{nmap,xml,gnmap}"
}

nmap_vuln_scripts() {
    local target="$1" ports="$2"   # comma-separated open TCP ports
    local dir="$OUTDIR/nmap"; mkdir -p "$dir"
    section "NSE Vulnerability Scripts"
    check_tool nmap || return 1
    log_info "Running --script vuln against known-open ports (can be slow/loud, CTF-only)..."
    nmap -p "$ports" --script vuln -oN "$dir/vuln_scripts.txt" "$target" &>/dev/null
    log_success "vuln scripts -> $dir/vuln_scripts.txt"
    grep -qi "VULNERABLE" "$dir/vuln_scripts.txt" 2>/dev/null && \
        log_error "Findings flagged VULNERABLE — review $dir/vuln_scripts.txt"
}

ssl_tls_scan() {
    local target="$1" port="$2"
    local dir="$OUTDIR/ssl"; mkdir -p "$dir"
    section "SSL/TLS Scan ($target:$port)"

    if check_tool sslscan "apt install sslscan"; then
        run_capped 60 "$dir/sslscan_${port}.txt" -- sslscan "$target:$port"
        log_success "sslscan -> $dir/sslscan_${port}.txt"
    elif check_tool nmap; then
        log_info "sslscan not found, falling back to nmap ssl-enum-ciphers..."
        nmap -p "$port" --script "ssl-enum-ciphers,ssl-cert,ssl-heartbleed" \
            -oN "$dir/nmap_ssl_${port}.txt" "$target" &>/dev/null
        log_success "nmap SSL scripts -> $dir/nmap_ssl_${port}.txt"
    else
        log_warn "Neither sslscan nor nmap available for TLS check."
    fi
}
