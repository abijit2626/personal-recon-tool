# shellcheck shell=bash
# shellcheck source=../recon.sh

# =============================================================================
# web.sh — web content discovery (dir-busting, archive URLs, nikto)
# =============================================================================

web_content_discovery() {
    local url="$1"
    local safe_name; safe_name=$(echo "$url" | sed -E 's#https?://##; s/[^a-zA-Z0-9.]/_/g')
    local dir="$OUTDIR/web/$safe_name"; mkdir -p "$dir"
    section "Web Content Discovery ($url)"

    local wordlist="${WORDLIST:-}"
    if [[ -z "$wordlist" ]]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
        [[ -f "$wordlist" ]] || wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
    fi

    if check_tool feroxbuster "apt install feroxbuster"; then
        log_info "Running feroxbuster (preferred, recursive)..."
        feroxbuster -u "$url" -w "$wordlist" -t 50 -q \
            -o "$dir/feroxbuster.txt" 2>/dev/null
        log_success "feroxbuster -> $dir/feroxbuster.txt"
    elif check_tool gobuster "apt install gobuster"; then
        log_info "Running gobuster dir..."
        run_capped 120 "$dir/gobuster.txt" -- gobuster dir -u "$url" -w "$wordlist" -q -t 50
        log_success "gobuster -> $dir/gobuster.txt"
    elif check_tool ffuf "apt install ffuf"; then
        log_info "Running ffuf..."
        ffuf -u "${url%/}/FUZZ" -w "$wordlist" -mc 200,204,301,302,307,401,403 \
            -o "$dir/ffuf.json" -of json -s
        log_success "ffuf -> $dir/ffuf.json"
    else
        log_warn "No dir-brute tool found (feroxbuster/gobuster/ffuf) — skipping."
    fi

    if check_tool gau "go install github.com/lc/gau"; then
        log_info "Pulling historical URLs via gau..."
        run_capped 60 "$dir/gau.txt" -- gau --subs "$(echo "$url" | sed -E 's#https?://##')"
        log_success "gau -> $dir/gau.txt"
    elif check_tool waybackurls "go install github.com/tomnomnom/waybackurls"; then
        log_info "Pulling historical URLs via waybackurls..."
        echo "$url" | sed -E 's#https?://##' | run_capped 60 "$dir/waybackurls.txt" -- waybackurls
        log_success "waybackurls -> $dir/waybackurls.txt"
    else
        log_warn "No archive-URL tool found (gau/waybackurls) — skipping."
    fi

    if check_tool nikto "apt install nikto"; then
        log_info "Running nikto (this can take a bit)..."
        run_capped 180 "$dir/nikto.txt" -- nikto -h "$url" -Tuning x
        log_success "nikto -> $dir/nikto.txt"
    fi
}
