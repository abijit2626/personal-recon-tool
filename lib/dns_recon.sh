# shellcheck shell=bash
# shellcheck source=../recon.sh

# =============================================================================
# dns_recon.sh — DNS enumeration and reverse DNS sweep
# =============================================================================

dns_recon() {
    local domain="$1"
    local dir="$OUTDIR/dns"; mkdir -p "$dir"
    section "DNS Reconnaissance ($domain)"

    if ! check_tool dig "apt install dnsutils"; then
        log_error "dig missing — DNS recon phase skipped entirely."
        return 1
    fi

    log_info "Pulling standard records..."
    for rtype in A AAAA MX NS TXT SOA; do
        dig +short "$rtype" "$domain" >"$dir/${rtype,,}.txt" 2>&1
    done
    log_success "Records saved under $dir/{a,aaaa,mx,ns,txt,soa}.txt"

    log_info "Attempting zone transfer against each NS..."
    while read -r ns; do
        [[ -z "$ns" ]] && continue
        log_info "  -> AXFR against $ns"
        local result
        result=$(dig axfr "$domain" "@$ns" 2>&1)
        if echo "$result" | grep -qi "Transfer failed\|connection timed out\|refused"; then
            log_warn "  Zone transfer refused by $ns"
        else
            echo "$result" >"$dir/axfr_${ns//[^a-zA-Z0-9.]/_}.txt"
            log_error "  ZONE TRANSFER SUCCEEDED on $ns — see $dir/axfr_${ns//[^a-zA-Z0-9.]/_}.txt"
        fi
    done < "$dir/ns.txt"

    log_info "Subdomain enumeration..."
    local sub_found=0
    if check_tool subfinder "apt install subfinder / go install"; then
        run_capped 60 "$dir/subfinder.txt" -- subfinder -d "$domain" -silent
        sub_found=1
    fi
    if check_tool amass "apt install amass"; then
        log_info "amass (passive, capped at 90s for CTF speed)..."
        run_capped 90 "$dir/amass.txt" -- amass enum -passive -d "$domain"
        sub_found=1
    fi
    if check_tool assetfinder "go install github.com/tomnomnom/assetfinder"; then
        run_capped 45 "$dir/assetfinder.txt" -- assetfinder --subs-only "$domain"
        sub_found=1
    fi
    [[ $sub_found -eq 0 ]] && log_warn "No subdomain tool installed (subfinder/amass/assetfinder) — skipped."

    if [[ $sub_found -eq 1 ]]; then
        cat "$dir"/{subfinder,amass,assetfinder}.txt 2>/dev/null | sort -u >"$dir/subdomains_merged.txt"
        log_success "Merged unique subdomains -> $dir/subdomains_merged.txt ($(wc -l < "$dir/subdomains_merged.txt") found)"
    fi
}

reverse_dns_sweep() {
    local ip_list_file="$1"
    local dir="$OUTDIR/dns"; mkdir -p "$dir"
    section "Reverse DNS Sweep"
    check_tool dig || return 1

    : >"$dir/reverse_dns.txt"
    while read -r ip; do
        [[ -z "$ip" ]] && continue
        local ptr
        ptr=$(dig +short -x "$ip")
        [[ -n "$ptr" ]] && echo "$ip -> $ptr" >>"$dir/reverse_dns.txt"
    done < "$ip_list_file"
    log_success "Reverse DNS results -> $dir/reverse_dns.txt"
}
