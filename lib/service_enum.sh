# shellcheck shell=bash
# shellcheck source=../ghost.sh

# =============================================================================
# service_enum.sh — service-specific enumeration dispatchers
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
# DISPATCH TABLE
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
        *) : ;;
    esac
}

# =============================================================================
# DRIVER — parse nmap grepable output and dispatch
# =============================================================================
run_service_enum_phase() {
    local target="$1" grepable_file="$2"
    section "Service-Specific Enumeration Phase"

    if [[ ! -f "$grepable_file" ]]; then
        log_warn "No greppable nmap output found at $grepable_file, skipping service enum."
        return 1
    fi

    grep -oP '\d+/open/(tcp|udp)' "$grepable_file" | while read -r entry; do
        local port="${entry%%/*}"
        local proto; proto=$(echo "$entry" | cut -d'/' -f2)
        log_info "Dispatching enumerator for $port/$proto..."
        dispatch_service_enum "$target" "$port" "$proto"
    done
}
