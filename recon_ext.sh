#!/usr/bin/env bash
# =============================================================================
# recon_ext.sh — extension module for recon.sh
#
# Source this from your main script AFTER your existing color/log helpers,
# RECON_HOME setup, and output-dir creation are already defined, e.g.:
#
#   source "$(dirname "$0")/recon_ext.sh"
#
# It assumes these already exist in recon.sh (rename in the compat shim
# below if yours differ):
#   - Color vars: RED GREEN YELLOW BLUE CYAN NC (or similar)
#   - log_info / log_warn / log_error / log_success / section()
#   - $OUTDIR   -> the timestamped run directory
#   - $TARGET   -> the IP or hostname being scanned
# =============================================================================

# --- compat shim: only defines these if your main script doesn't already ---
type log_info    >/dev/null 2>&1 || log_info()    { echo -e "${BLUE:-}[*]${NC:-} $*"; }
type log_warn    >/dev/null 2>&1 || log_warn()    { echo -e "${YELLOW:-}[!]${NC:-} $*"; }
type log_error   >/dev/null 2>&1 || log_error()   { echo -e "${RED:-}[-]${NC:-} $*"; }
type log_success >/dev/null 2>&1 || log_success() { echo -e "${GREEN:-}[+]${NC:-} $*"; }
type section      >/dev/null 2>&1 || section()    { echo -e "\n${CYAN:-}==== $* ====${NC:-}\n"; }

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

# =============================================================================
# PART 1 — SERVICE-SPECIFIC ENUMERATION (the big win)
# =============================================================================

# ---- 445/tcp SMB -------------------------------------------------------
enum_smb() {
    local target="$1" port="$2"
    local dir="$OUTDIR/smb"; mkdir -p "$dir"
    section "SMB Enumeration ($target:$port)"

    if check_tool enum4linux "apt install enum4linux"; then
        log_info "Running enum4linux -a ..."
        run_capped 90 "$dir/enum4linux.txt" -- enum4linux -a "$target"
        log_success "enum4linux -> $dir/enum4linux.txt"
    fi

    if check_tool smbclient "apt install smbclient"; then
        log_info "Testing null session share list..."
        if smbclient -L "//$target/" -N -g >"$dir/smbclient_shares.txt" 2>&1; then
            log_success "Null session ALLOWED — shares -> $dir/smbclient_shares.txt"
        else
            log_warn "Null session denied or no shares listed."
        fi
    fi

    if check_tool smbmap "apt install smbmap"; then
        log_info "Running smbmap (null session share perms)..."
        run_capped 60 "$dir/smbmap.txt" -- smbmap -H "$target" -u null -p ""
        log_success "smbmap -> $dir/smbmap.txt"
    fi

    if check_tool nmap "-"; then
        log_info "Running SMB NSE script sweep (vuln + enum, non-intrusive set)..."
        nmap -p "$port" --script "smb-os-discovery,smb-enum-shares,smb-enum-users,smb2-security-mode,smb-vuln-ms17-010" \
            -oN "$dir/nmap_smb_scripts.txt" "$target" &>/dev/null
        log_success "nmap SMB scripts -> $dir/nmap_smb_scripts.txt"
        if grep -qi "VULNERABLE" "$dir/nmap_smb_scripts.txt" 2>/dev/null; then
            log_error "Possible EternalBlue (MS17-010) exposure detected — check $dir/nmap_smb_scripts.txt"
        fi
    fi
}

# ---- 21/tcp FTP ---------------------------------------------------------
enum_ftp() {
    local target="$1" port="$2"
    local dir="$OUTDIR/ftp"; mkdir -p "$dir"
    section "FTP Enumeration ($target:$port)"

    log_info "Testing anonymous login..."
    if check_tool ftp; then
        {
            echo "open $target $port"
            echo "user anonymous anonymous"
            echo "ls"
            echo "bye"
        } | ftp -n -v >"$dir/ftp_anon_attempt.txt" 2>&1
        if grep -qiE "230|Login successful" "$dir/ftp_anon_attempt.txt"; then
            log_error "Anonymous FTP login ALLOWED — see $dir/ftp_anon_attempt.txt"
        else
            log_warn "Anonymous FTP login denied (or ftp client behaved oddly, check log)."
        fi
    fi

    if check_tool nmap; then
        log_info "Running nmap ftp-anon + ftp-syst..."
        nmap -p "$port" --script "ftp-anon,ftp-syst" -oN "$dir/nmap_ftp_scripts.txt" "$target" &>/dev/null
        log_success "nmap FTP scripts -> $dir/nmap_ftp_scripts.txt"
    fi
}

# ---- 161/udp SNMP --------------------------------------------------------
enum_snmp() {
    local target="$1" port="$2"
    local dir="$OUTDIR/snmp"; mkdir -p "$dir"
    section "SNMP Enumeration ($target:$port)"

    if check_tool onesixtyone "apt install onesixtyone"; then
        log_info "Brute-forcing common community strings..."
        local wordlist="/usr/share/seclists/Discovery/SNMP/snmp.txt"
        [[ -f "$wordlist" ]] || wordlist=<(printf "public\nprivate\nmanager\ncisco\n")
        run_capped 60 "$dir/onesixtyone.txt" -- onesixtyone -c "$wordlist" "$target"
        log_success "onesixtyone -> $dir/onesixtyone.txt"
    fi

    if check_tool snmpwalk "apt install snmp"; then
        log_info "Walking with community 'public'..."
        run_capped 60 "$dir/snmpwalk_public.txt" -- snmpwalk -v2c -c public "$target"
        if [[ -s "$dir/snmpwalk_public.txt" ]] && ! grep -qi "timeout\|no response" "$dir/snmpwalk_public.txt"; then
            log_error "SNMP community 'public' is READABLE — see $dir/snmpwalk_public.txt"
        fi
    fi
}

# ---- 22/tcp SSH -----------------------------------------------------------
enum_ssh() {
    local target="$1" port="$2"
    local dir="$OUTDIR/ssh"; mkdir -p "$dir"
    section "SSH Enumeration ($target:$port)"

    log_info "Grabbing banner..."
    (echo "" | timeout 5 nc "$target" "$port" 2>/dev/null | head -n1) >"$dir/banner.txt"
    [[ -s "$dir/banner.txt" ]] && log_success "Banner: $(cat "$dir/banner.txt")"

    if check_tool nmap; then
        log_info "Running ssh2-enum-algos + ssh-hostkey..."
        nmap -p "$port" --script "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" \
            -oN "$dir/nmap_ssh_scripts.txt" "$target" &>/dev/null
        log_success "nmap SSH scripts -> $dir/nmap_ssh_scripts.txt"
    fi
}

# ---- 3306/tcp MySQL ---------------------------------------------------
enum_mysql() {
    local target="$1" port="$2"
    local dir="$OUTDIR/mysql"; mkdir -p "$dir"
    section "MySQL Enumeration ($target:$port)"

    if check_tool mysql "apt install mysql-client / mariadb-client"; then
        log_info "Testing root with empty password..."
        if timeout 10 mysql -h "$target" -P "$port" -u root --password="" -e "SELECT VERSION();" \
            >"$dir/mysql_root_empty.txt" 2>&1; then
            log_error "MySQL root login with EMPTY password succeeded — see $dir/mysql_root_empty.txt"
        else
            log_warn "MySQL root/empty-password login failed (expected on hardened boxes)."
        fi
    fi

    if check_tool nmap; then
        log_info "Running mysql-info + mysql-empty-password NSE..."
        nmap -p "$port" --script "mysql-info,mysql-empty-password" \
            -oN "$dir/nmap_mysql_scripts.txt" "$target" &>/dev/null
        log_success "nmap MySQL scripts -> $dir/nmap_mysql_scripts.txt"
    fi
}

# ---- 6379/tcp Redis ------------------------------------------------------
enum_redis() {
    local target="$1" port="$2"
    local dir="$OUTDIR/redis"; mkdir -p "$dir"
    section "Redis Enumeration ($target:$port)"

    if check_tool redis-cli "apt install redis-tools"; then
        log_info "Attempting INFO without auth..."
        run_capped 10 "$dir/redis_info.txt" -- redis-cli -h "$target" -p "$port" INFO
        if [[ -s "$dir/redis_info.txt" ]] && ! grep -qi "NOAUTH\|denied" "$dir/redis_info.txt"; then
            log_error "Redis accessible WITHOUT auth — see $dir/redis_info.txt"
            log_info "Grabbing keyspace summary..."
            run_capped 15 "$dir/redis_keys_sample.txt" -- redis-cli -h "$target" -p "$port" --scan --count 100
        else
            log_warn "Redis requires auth (or unreachable)."
        fi
    fi
}

# ---- 27017/tcp MongoDB ---------------------------------------------------
enum_mongodb() {
    local target="$1" port="$2"
    local dir="$OUTDIR/mongodb"; mkdir -p "$dir"
    section "MongoDB Enumeration ($target:$port)"

    if check_tool nmap; then
        log_info "Running mongodb-info / mongodb-databases NSE..."
        nmap -p "$port" --script "mongodb-info,mongodb-databases" \
            -oN "$dir/nmap_mongo_scripts.txt" "$target" &>/dev/null
        if grep -qi "databases" "$dir/nmap_mongo_scripts.txt" 2>/dev/null; then
            log_error "MongoDB appears reachable WITHOUT auth — see $dir/nmap_mongo_scripts.txt"
        fi
        log_success "nmap Mongo scripts -> $dir/nmap_mongo_scripts.txt"
    fi

    if check_tool mongosh || check_tool mongo; then
        local client; command -v mongosh &>/dev/null && client=mongosh || client=mongo
        log_info "Attempting unauthenticated listDatabases via $client..."
        run_capped 10 "$dir/mongo_dbs.txt" -- "$client" --host "$target" --port "$port" \
            --eval "db.adminCommand('listDatabases')" --quiet
    fi
}

# ---- 111/135 RPC ----------------------------------------------------------
enum_rpc() {
    local target="$1" port="$2"
    local dir="$OUTDIR/rpc"; mkdir -p "$dir"
    section "RPC Enumeration ($target:$port)"

    if check_tool rpcinfo "apt install rpcbind"; then
        log_info "Querying rpcinfo -p..."
        run_capped 20 "$dir/rpcinfo.txt" -- rpcinfo -p "$target"
        log_success "rpcinfo -> $dir/rpcinfo.txt"
    fi

    if check_tool nmap; then
        log_info "Running rpc-grind + rpcinfo NSE..."
        nmap -p "$port" --script "rpc-grind,rpcinfo" -oN "$dir/nmap_rpc_scripts.txt" "$target" &>/dev/null
        log_success "nmap RPC scripts -> $dir/nmap_rpc_scripts.txt"
    fi
}

# =============================================================================
# DISPATCH TABLE — the actual branch-on-open-ports logic
#
# Call dispatch_service_enum once per open port. It's a pure case statement
# so adding a new service later is a 3-line diff, not a rewrite.
#
# Expects: dispatch_service_enum <target> <port> <proto:tcp|udp>
# =============================================================================
dispatch_service_enum() {
    local target="$1" port="$2" proto="${3:-tcp}"

    case "$port" in
        445)   enum_smb     "$target" "$port" ;;
        21)    enum_ftp     "$target" "$port" ;;
        161)   [[ "$proto" == "udp" ]] && enum_snmp "$target" "$port" ;;
        22)    enum_ssh     "$target" "$port" ;;
        3306)  enum_mysql   "$target" "$port" ;;
        6379)  enum_redis   "$target" "$port" ;;
        27017) enum_mongodb "$target" "$port" ;;
        111|135) enum_rpc   "$target" "$port" ;;
        *) : ;;  # no specific enumerator for this port — silently skip
    esac
}

# Driver: parse your nmap greppable/normal output and fan out.
# Assumes you already have a function producing lines like "PORT/PROTO" for
# open ports (adapt the parse to whatever your existing nmap wrapper emits).
# If you used `nmap -oG`, this parses it directly:
run_service_enum_phase() {
    local target="$1" grepable_file="$2"
    section "Service-Specific Enumeration Phase"

    if [[ ! -f "$grepable_file" ]]; then
        log_warn "No greppable nmap output found at $grepable_file, skipping service enum."
        return 1
    fi

    # Extract "port/proto" for each open port, e.g. "445/tcp" "161/udp"
    grep -oP '\d+/(tcp|udp)/open' "$grepable_file" | while read -r entry; do
        local port="${entry%%/*}"
        local proto; proto=$(echo "$entry" | cut -d'/' -f2)
        log_info "Dispatching enumerator for $port/$proto..."
        dispatch_service_enum "$target" "$port" "$proto"
    done
}

# =============================================================================
# PART 2 — DNS RECONNAISSANCE (domain targets only)
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

# Reverse DNS sweep for a list of IPs (e.g. a /24 you found in-scope)
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

# =============================================================================
# PART 3 — WEB CONTENT DISCOVERY
# =============================================================================
web_content_discovery() {
    local url="$1"   # e.g. http://target:80
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

# =============================================================================
# PART 4 — ADVANCED NMAP PHASES
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

# =============================================================================
# PART 5 — SCREENSHOTTING
# =============================================================================
screenshot_web_targets() {
    local url_list_file="$1"   # one URL per line
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

# =============================================================================
# PART 6 — HTML REPORT GENERATION
# Walks $OUTDIR and builds a single self-contained report.html.
# =============================================================================
generate_html_report() {
    local target="$1"
    local out="$OUTDIR/report.html"
    section "Generating HTML Report"

    {
        cat <<HTML
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Recon Report: $target</title>
<style>
body{font-family:ui-monospace,Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:2rem;}
h1{color:#58a6ff;} h2{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:.3rem;margin-top:2rem;}
pre{background:#161b22;padding:1rem;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;}
.warn{color:#d29922;} .bad{color:#f85149;} .good{color:#3fb950;}
.meta{color:#8b949e;font-size:.9em;}
img{max-width:400px;border:1px solid #30363d;border-radius:4px;margin:.5rem;}
</style></head><body>
<h1>Recon Report — $target</h1>
<p class="meta">Generated $(date '+%Y-%m-%d %H:%M:%S')</p>
HTML

        # Nmap section
        if [[ -f "$OUTDIR/nmap/scan.txt" || -f "$OUTDIR"/scan.nmap ]]; then
            echo "<h2>Nmap</h2><pre>"
            find "$OUTDIR" -maxdepth 2 \( -iname "*.nmap" -o -iname "scan.txt" \) 2>/dev/null | while read -r f; do
                echo "--- $f ---"; sed 's/</\&lt;/g; s/>/\&gt;/g' "$f"
            done
            echo "</pre>"
        fi

        # Service-specific findings
        for svc_dir in smb ftp snmp ssh mysql redis mongodb rpc; do
            [[ -d "$OUTDIR/$svc_dir" ]] || continue
            echo "<h2>${svc_dir^^}</h2><pre>"
            for f in "$OUTDIR/$svc_dir"/*; do
                [[ -f "$f" ]] || continue
                echo "--- $(basename "$f") ---"
                sed 's/</\&lt;/g; s/>/\&gt;/g' "$f"
                echo
            done
            echo "</pre>"
        done

        # DNS
        if [[ -d "$OUTDIR/dns" ]]; then
            echo "<h2>DNS</h2><pre>"
            for f in "$OUTDIR/dns"/*; do
                [[ -f "$f" ]] || continue
                echo "--- $(basename "$f") ---"
                sed 's/</\&lt;/g; s/>/\&gt;/g' "$f"
                echo
            done
            echo "</pre>"
        fi

        # Web
        if [[ -d "$OUTDIR/web" ]]; then
            echo "<h2>Web Content Discovery</h2><pre>"
            find "$OUTDIR/web" -type f 2>/dev/null | while read -r f; do
                echo "--- $f ---"
                sed 's/</\&lt;/g; s/>/\&gt;/g' "$f" | head -c 5000
                echo
            done
            echo "</pre>"
        fi

        # Screenshots
        if [[ -d "$OUTDIR/screenshots" ]]; then
            echo "<h2>Screenshots</h2>"
            find "$OUTDIR/screenshots" -iname "*.png" -o -iname "*.jpg" 2>/dev/null | while read -r img; do
                echo "<img src=\"${img#"$OUTDIR"/}\" alt=\"$(basename "$img")\">"
            done
        fi

        echo "</body></html>"
    } >"$out"

    log_success "HTML report -> $out"
}
