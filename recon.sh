#!/bin/bash
#
# recon.sh - Interactive recon shell for CTFs
#
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
WHITE='\033[1;37m'; PURPLE='\033[0;35m'

# Global log helpers (used by lib modules)
log_info()    { echo -e "${CYAN}[*]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()   { echo -e "${RED}[-]${NC} $*"; }
log_success() { echo -e "${GREEN}[+]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/core.sh
for _mod in core network service_enum dns_recon web screenshot report; do
    source "${SCRIPT_DIR}/lib/${_mod}.sh"
done

TARGET=""
OUTDIR=""
TMP_OUT=""

cleanup() { [ -n "$TMP_OUT" ] && rm -f "$TMP_OUT"; }
trap cleanup EXIT

int_handler() { echo -e "\n${YELLOW}[!] Interrupted.${NC}"; cleanup; exit 1; }
trap int_handler INT TERM

print_banner() {
    echo -e "${WHITE}⠀⠀⠀⠀⠀⠀⢀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀${NC}  ${PURPLE} ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █ ${NC}"
    echo -e "${WHITE}⠀⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀⠀⠀⢀⣼⡇${NC}  ${PURPLE}▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ${NC}"
    echo -e "${WHITE}⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⣴⣿⣿⠃${NC}  ${PURPLE}▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒${NC}"
    echo -e "${WHITE}⠀⠀⠀⠀⢠⣿⣿⣿⣇⠀⠀⢀⣾⣿⣿⣿⠀${NC}  ${PURPLE}▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒${NC}"
    echo -e "${WHITE}⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⡟⠀${NC}  ${PURPLE}░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░${NC}"
    echo -e "${WHITE}⠀⠀⢰⡿⠉⠀⡜⣿⣿⣿⡿⠿⢿⣿⣿⠃⠀${NC}  ${PURPLE}░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ${NC}"
    echo -e "${WHITE}⠒⠒⠸⣿⣄⡘⣃⣿⣿⡟⢰⠃⠀⢹⣿⡇⠀${NC}  ${PURPLE}  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░${NC}"
    echo -e "${WHITE}⠚⠉⠀⠈⠻⣿⣿⣿⣿⣿⣮⣤⣤⣿⡟⠁⠀${NC}  ${PURPLE}  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░ ${NC}"
    echo -e "${WHITE}⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠛⠛⠛⠁⠀⠒⠤${NC}  ${PURPLE}   ░        ░  ░░ ░          ░ ░           ░ ${NC}"
    echo -e "${WHITE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠀⠀${NC}  ${PURPLE}                ░                            ${NC}"
}

show_usage() {
    echo -e "${BOLD}Usage:${NC} $0 [options] <target>"
    echo "       $0               (interactive shell)"
    echo ""
    echo "Run reconnaissance on a target IP or domain."
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo -e "  ${GREEN}-o, --output <dir>${NC}    Custom output directory"
    echo -e "  ${GREEN}-p, --ports <range>${NC}   Port range (e.g. 1-1000, 22,80,443)"
    echo -e "  ${GREEN}-T, --timing <0-5>${NC}    Nmap timing template (default: 4)"
    echo -e "  ${GREEN}--no-web${NC}              Skip web fingerprinting"
    echo -e "  ${GREEN}--no-ping${NC}             Skip ping connectivity check"
    echo -e "  ${GREEN}-v, --verbose${NC}         Verbose nmap output"
    echo -e "  ${GREEN}--udp${NC}                 UDP top-50 scan (requires sudo)"
    echo -e "  ${GREEN}--vuln${NC}                Run NSE vulnerability scripts"
    echo -e "  ${GREEN}--screenshots${NC}         Screenshot web pages (gowitness/aquatone)"
    echo -e "  ${GREEN}--dns${NC}                 Force DNS recon (auto-detected for domains)"
    echo -e "  ${GREEN}--wordlist <path>${NC}     Custom wordlist for directory brute-force"
    echo -e "  ${GREEN}--fast${NC}                Skip UDP, vuln, screenshots (default)"
    echo -e "  ${GREEN}-h, --help${NC}            Show this help"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 scanme.nmap.org"
    echo "  $0 -p 22,80,443 -T3 10.10.10.1"
    echo "  $0 --no-web -o ~/scans/myscan example.com"
    echo "  $0 -v -T5 --no-ping 192.168.1.1"
}

check_deps() {
    local missing=()
    for cmd in nmap curl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing required tools: ${missing[*]}${NC}"
        echo "Install with: sudo apt install ${missing[*]}"
        exit 1
    fi
    if ! command -v whatweb &>/dev/null; then
        echo -e "${YELLOW}[!] whatweb not found - web fingerprinting will be limited.${NC}"
        echo "    Install with: sudo apt install whatweb"
    fi
}

get_output_dir() {
    # Non-interactive. Always resolves under $HOME/recon_output so it never
    # depends on (or fails because of) whatever directory recon was launched from.
    local target="$1"
    local parent_dir="${RECON_HOME:-$HOME/recon_output}"

    if ! mkdir -p "$parent_dir" 2>/dev/null; then
        echo -e "${RED}Error:${NC} Could not create base output directory '$parent_dir' (permission denied?)." >&2
        echo -e "${YELLOW}Tip:${NC} set RECON_HOME to a directory you can write to, e.g. RECON_HOME=~/scans recon <target>" >&2
        exit 1
    fi

    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local base="${parent_dir}/recon_${target//\//_}_${timestamp}"
    local candidate="$base"
    local n=2
    # Guard against same-second collisions instead of prompting to overwrite.
    while [ -e "$candidate" ]; do
        candidate="${base}_${n}"
        n=$((n + 1))
    done
    echo "$candidate"
}

run_scan() {
    local target="$1"
    local outdir="$2"
    local port_range="$3"
    local timing="$4"
    local skip_web="$5"
    local skip_ping="$6"
    local verbose="$7"
    local do_udp="${8:-false}"
    local do_vuln="${9:-false}"
    local do_screenshots="${10:-false}"
    local do_dns="${11:-auto}"
    local wordlist="${12:-}"

    local scan_start
    scan_start=$(date +%s)
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local web_ports=()

    if [ -z "$outdir" ]; then
        outdir="recon_${target//\//_}_${timestamp}"
    fi
    if [ -d "$outdir" ]; then
        # Non-interactive: never overwrite silently, never prompt. Just pick a
        # fresh, unused name so the scan always proceeds.
        local base="$outdir"
        local n=2
        while [ -e "$outdir" ]; do
            outdir="${base}_${n}"
            n=$((n + 1))
        done
        echo -e "${YELLOW}[!] Output directory existed, using: $outdir${NC}"
    fi

    local report="${outdir}/report.txt"
    TMP_OUT=$(mktemp /tmp/recon_XXXXXX.tmp)

    if ! mkdir -p "$outdir" 2>/dev/null; then
        echo -e "${RED}Error:${NC} Could not create output directory '$outdir' (permission denied?)." >&2
        echo -e "${YELLOW}Tip:${NC} pass -o/--output <dir> pointing somewhere you can write, or set RECON_HOME." >&2
        return 1
    fi

    # Export globals for lib modules
    # shellcheck disable=SC2034
    TARGET="$target"
    # shellcheck disable=SC2034
    OUTDIR="$outdir"
    # shellcheck disable=SC2034
    WORDLIST="$wordlist"

    log() {
        echo -e "$1"
        echo -e "$1" | sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g' >> "$report"
    }

    section() { log ""; log "${BOLD}${CYAN}== $1 ==${NC}"; }

    log "${BOLD}Recon report for: ${target}${NC}"
    log "Generated: $(date)"
    log "Output directory: ${outdir}"

    section "PORT SCAN (nmap -sV -T${timing})"
    log "${YELLOW}Running nmap... this can take a minute or two.${NC}"

    if ! $skip_ping && command -v ping &>/dev/null; then
        ping -c 1 -W 2 "$target" &>/dev/null || log "${YELLOW}Target not responding to ping — nmap will still try, but may take longer.${NC}"
    fi

    local nmap_args=(-sV -T"${timing}" --open -oA "$outdir/scan")
    $verbose && nmap_args+=(-v)
    [ -n "$port_range" ] && nmap_args+=(-p "$port_range")
    nmap "${nmap_args[@]}" "$target" > "$TMP_OUT" 2>&1
    local nmap_exit=$?

    if [ $nmap_exit -ne 0 ]; then
        log "${RED}nmap failed (exit code $nmap_exit). Error output:${NC}"
        [ -f "$TMP_OUT" ] && sed 's/^/  /' < "$TMP_OUT" >> "$report"
        [ -f "$TMP_OUT" ] && sed 's/^/  /' < "$TMP_OUT"
        return 1
    fi

    local nmap_normal="${outdir}/scan.nmap"
    mapfile -t open_ports < <(grep -E '^[0-9]+/tcp\s+open' "$nmap_normal" | awk '{print $1":"$3}')

    if [ ${#open_ports[@]} -eq 0 ]; then
        log "${YELLOW}No open TCP ports found (or host is filtering/down). Stopping here.${NC}"
        log ""; log "Full report saved to: ${report}"
        return 0
    fi

    section "OPEN PORTS SUMMARY"
    for entry in "${open_ports[@]}"; do
        log "  ${GREEN}${entry}${NC}"
    done

    local web_port_count=0
    if ! $skip_web; then
        section "WEB FINGERPRINTING"
        local web_ports_found=0

        for entry in "${open_ports[@]}"; do
            local port="${entry%%/*}"
            local service="${entry##*:}"

            case "$service" in
                http|https|http-proxy|http-alt|ssl/http)
                    web_ports_found=1
                    web_port_count=$((web_port_count + 1))
                    local scheme="http"
                    [[ "$service" == *https* || "$service" == *ssl* ]] && scheme="https"
                    local url="${scheme}://${target}:${port}"
                    web_ports+=("$scheme:$port")

                    log ""
                    log "${BOLD}--> ${url}${NC}"

                    local headers
                    headers=$(curl -s -k -I -m 8 "$url")
                    if [ -n "$headers" ]; then
                        log "  Headers:"
                        printf '%s\n' "$headers" | sed 's/^/    /' | tee -a "$report"
                    else
                        log "  ${YELLOW}No response to HEAD request (site may block HEAD or be slow).${NC}"
                    fi

                    local title
                    title=$(curl -s -k -m 8 --max-filesize 200K "$url" | tr -d '\n\r' | grep -oPi '(?<=<title>)(.*?)(?=</title>)' | head -1)
                    [ -n "$title" ] && log "  Title: ${title}"

                    local robots
                    robots=$(curl -s -k -m 8 -o /dev/null -w "%{http_code}" "${url}/robots.txt")
                    if [ "$robots" == "200" ]; then
                        log "  ${GREEN}robots.txt found${NC} -> ${url}/robots.txt"
                        curl -s -k -m 8 "${url}/robots.txt" >> "${outdir}/robots_${port}.txt"
                        log "    (saved to ${outdir}/robots_${port}.txt)"
                    fi

                    if command -v whatweb &>/dev/null; then
                        log "  Tech fingerprint (whatweb):"
                        whatweb -q "$url" 2>/dev/null | sed 's/^/    /' | sed -r 's/\x1B\[[0-9;]*[a-zA-Z]//g' | tee -a "$report"
                    fi
                    ;;
            esac
        done

        [ "$web_ports_found" -eq 0 ] && log "  No HTTP/HTTPS services detected."
    fi

    # ---- Extended phases (recon_ext.sh) ----
    local nmap_grep="${outdir}/scan.gnmap"

    run_service_enum_phase "$target" "$nmap_grep"

    # DNS recon: auto for domains, forced with --dns
    if [[ "$do_dns" == "true" ]] || { [[ "$do_dns" == "auto" ]] && [[ "$target" =~ [a-zA-Z] ]] && ! [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }; then
        dns_recon "$target"
    fi

    if ! $skip_web && [ ${#web_ports[@]} -gt 0 ]; then
        : > "$outdir/web_urls.txt"
        for we in "${web_ports[@]}"; do
            local w_scheme="${we%%:*}"
            local w_port="${we##*:}"
            local w_url="${w_scheme}://${target}:${w_port}"

            web_content_discovery "$w_url"
            [[ "$w_scheme" == "https" ]] && ssl_tls_scan "$target" "$w_port"

            echo "$w_url" >> "$outdir/web_urls.txt"
        done

        if [[ "$do_screenshots" == "true" ]] && [[ -s "$outdir/web_urls.txt" ]]; then
            screenshot_web_targets "$outdir/web_urls.txt"
        fi
    fi

    if [[ "$do_vuln" == "true" ]]; then
        local comma_ports
        comma_ports=$(printf '%s,' "${open_ports[@]%%/*}" | sed 's/,$//')
        nmap_vuln_scripts "$target" "$comma_ports"
    fi

    if [[ "$do_udp" == "true" ]]; then
        nmap_udp_scan "$target"
    fi

    generate_html_report "$target"

    # ---- Summary ----
    local scan_elapsed=$(( $(date +%s) - scan_start ))
    section "SUMMARY"
    log "  ${GREEN}Target:${NC}      ${target}"
    log "  ${GREEN}Ports open:${NC}  ${#open_ports[@]}"
    [ "$web_port_count" -gt 0 ] && log "  ${GREEN}Web services:${NC} ${web_port_count}"
    log "  ${GREEN}Duration:${NC}    ${scan_elapsed}s"
    log ""
    log "  ${DIM}Report:  ${report}${NC}"
    log "  ${DIM}Raw:     ${outdir}/scan.nmap${NC}"

    rm -f "$TMP_OUT"
}

interactive_shell() {
    check_deps
    print_banner
    echo -e "${CYAN}${BOLD}   RECON SHELL${NC} — type ${GREEN}help${NC} for commands"
    echo ""

    local target=""
    local outdir=""
    local port_range=""
    local timing="4"
    local skip_web=false
    local skip_ping=false
    local verbose=false
    local do_udp=false
    local do_vuln=false
    local do_screenshots=false
    local do_dns="auto"
    local wordlist=""

    while true; do
        echo -ne "${BOLD}recon${NC}${DIM}>${NC} "
        read -r cmd args
        [ -z "$cmd" ] && continue

        case "$cmd" in
            help|h|\?)
                echo -e "${BOLD}Commands:${NC}"
                echo -e "  ${GREEN}scan${NC} [target]        Run full recon scan"
                echo -e "  ${GREEN}set${NC}  <option> <val>  Set option (target, ports, timing,"
                echo -e "                          output, skip-web, skip-ping, verbose,"
                echo -e "                          udp, vuln, screenshots, dns, wordlist)"
                echo -e "  ${GREEN}show${NC} [options]       Show current settings"
                echo -e "  ${GREEN}help${NC}                 Show this help"
                echo -e "  ${GREEN}exit${NC}                 Exit the shell"
                ;;

            scan)
                local scan_target="${args:-$target}"
                if [ -z "$scan_target" ]; then
                    echo -e "${RED}Error:${NC} No target set. Use ${YELLOW}set target <ip/domain>${NC} or ${YELLOW}scan <target>${NC}"
                else
                    run_scan "$scan_target" "$outdir" "$port_range" "$timing" "$skip_web" "$skip_ping" "$verbose" "$do_udp" "$do_vuln" "$do_screenshots" "$do_dns" "$wordlist"
                fi
                ;;

            set)
                local opt val
                opt=$(printf '%s\n' "$args" | awk '{print $1}')
                val=$(printf '%s\n' "$args" | cut -d' ' -f2- | sed 's/^[[:space:]]*//')
                case "$opt" in
                    target)   target="$val"; echo -e "  ${GREEN}target${NC} -> ${target}" ;;
                    ports)    port_range="$val"; echo -e "  ${GREEN}ports${NC} -> ${port_range}" ;;
                    timing)   timing="$val"; echo -e "  ${GREEN}timing${NC} -> ${timing}" ;;
                    output)   outdir="$val"; echo -e "  ${GREEN}output${NC} -> ${outdir}" ;;
                    skip-web)
                        if [ -z "$val" ] || [ "$val" = true ]; then
                            skip_web=true
                        elif [ "$val" = false ]; then
                            skip_web=false
                        else
                            echo -e "${YELLOW}Invalid value:${NC} $val (use true or false)"
                            continue
                        fi
                        echo -e "  ${GREEN}skip-web${NC} -> ${skip_web}"
                        ;;
                    skip-ping)
                        if [ -z "$val" ] || [ "$val" = true ]; then
                            skip_ping=true
                        elif [ "$val" = false ]; then
                            skip_ping=false
                        else
                            echo -e "${YELLOW}Invalid value:${NC} $val (use true or false)"
                            continue
                        fi
                        echo -e "  ${GREEN}skip-ping${NC} -> ${skip_ping}"
                        ;;
                    verbose)
                        if [ -z "$val" ] || [ "$val" = true ]; then
                            verbose=true
                        elif [ "$val" = false ]; then
                            verbose=false
                        else
                            echo -e "${YELLOW}Invalid value:${NC} $val (use true or false)"
                            continue
                        fi
                        echo -e "  ${GREEN}verbose${NC} -> ${verbose}"
                        ;;
                    udp)
                        if [ -z "$val" ] || [ "$val" = true ]; then
                            do_udp=true
                        elif [ "$val" = false ]; then
                            do_udp=false
                        else
                            echo -e "${YELLOW}Invalid value:${NC} $val (use true or false)"
                            continue
                        fi
                        echo -e "  ${GREEN}udp${NC} -> ${do_udp}"
                        ;;
                    vuln)
                        if [ -z "$val" ] || [ "$val" = true ]; then
                            do_vuln=true
                        elif [ "$val" = false ]; then
                            do_vuln=false
                        else
                            echo -e "${YELLOW}Invalid value:${NC} $val (use true or false)"
                            continue
                        fi
                        echo -e "  ${GREEN}vuln${NC} -> ${do_vuln}"
                        ;;
                    screenshots)
                        if [ -z "$val" ] || [ "$val" = true ]; then
                            do_screenshots=true
                        elif [ "$val" = false ]; then
                            do_screenshots=false
                        else
                            echo -e "${YELLOW}Invalid value:${NC} $val (use true or false)"
                            continue
                        fi
                        echo -e "  ${GREEN}screenshots${NC} -> ${do_screenshots}"
                        ;;
                    dns)
                        if [ -z "$val" ] || [ "$val" = true ]; then
                            do_dns=true
                        elif [ "$val" = false ]; then
                            do_dns=false
                        elif [ "$val" = auto ]; then
                            do_dns=auto
                        else
                            echo -e "${YELLOW}Invalid value:${NC} $val (use true, false, or auto)"
                            continue
                        fi
                        echo -e "  ${GREEN}dns${NC} -> ${do_dns}"
                        ;;
                    wordlist)
                        wordlist="$val"
                        echo -e "  ${GREEN}wordlist${NC} -> ${wordlist}"
                        ;;
                    unset)
                        local uopt="$val"
                        case "$uopt" in
                            target) target="" ;;
                            ports) port_range="" ;;
                            output) outdir="" ;;
                            skip-web) skip_web=false ;;
                            skip-ping) skip_ping=false ;;
                            verbose) verbose=false ;;
                            udp) do_udp=false ;;
                            vuln) do_vuln=false ;;
                            screenshots) do_screenshots=false ;;
                            dns) do_dns=auto ;;
                            wordlist) wordlist="" ;;
                            *) echo -e "${YELLOW}Unknown option:${NC} $uopt" ;;
                        esac
                        [ -n "$uopt" ] && echo -e "  ${YELLOW}$uopt${NC} -> unset"
                        ;;
                    *)
                        echo -e "${YELLOW}Unknown option:${NC} $opt"
                        echo "  Options: target, ports, timing, output, skip-web, skip-ping, verbose, udp, vuln, screenshots, dns, wordlist"
                        echo "  Use: set unset <option> to clear a value"
                        ;;
                esac
                ;;

            show)
                case "${args%% *}" in
                    options|"")
                        echo -e "${BOLD}Current Settings:${NC}"
                        echo -e "  ${GREEN}target${NC}      = ${target:-${DIM}(not set)${NC}}"
                        echo -e "  ${GREEN}ports${NC}       = ${port_range:-${DIM}(default: all)${NC}}"
                        echo -e "  ${GREEN}timing${NC}      = ${timing}"
                        echo -e "  ${GREEN}output${NC}      = ${outdir:-${DIM}(auto-generated)${NC}}"
                        echo -e "  ${GREEN}skip-web${NC}    = ${skip_web}"
                        echo -e "  ${GREEN}skip-ping${NC}   = ${skip_ping}"
                        echo -e "  ${GREEN}verbose${NC}     = ${verbose}"
                        echo -e "  ${GREEN}udp${NC}         = ${do_udp}"
                        echo -e "  ${GREEN}vuln${NC}        = ${do_vuln}"
                        echo -e "  ${GREEN}screenshots${NC} = ${do_screenshots}"
                        echo -e "  ${GREEN}dns${NC}         = ${do_dns}"
                        echo -e "  ${GREEN}wordlist${NC}    = ${wordlist:-${DIM}(default)${NC}}"
                        ;;
                    *)  echo -e "${YELLOW}Usage:${NC} show options" ;;
                esac
                ;;

            exit|quit)
                echo -e "${YELLOW}Bye.${NC}"
                break
                ;;

            *)
                echo -e "${YELLOW}Unknown command:${NC} $cmd (type ${GREEN}help${NC})"
                ;;
        esac
    done
}

if [ $# -eq 0 ]; then
    # No target given -> straight into the interactive shell. No prompts.
    interactive_shell
else
    local_outdir=""
    local_port_range=""
    local_timing="4"
    local_skip_web=false
    local_skip_ping=false
    local_verbose=false
    local_do_udp=false
    local_do_vuln=false
    local_do_screenshots=false
    local_do_dns=false
    local_wordlist=""
    local_target=""

    while [ $# -gt 0 ]; do
        case "$1" in
            -o|--output)   local_outdir="$2"; shift 2 ;;
            -p|--ports)    local_port_range="$2"; shift 2 ;;
            -T|--timing)   local_timing="$2"; shift 2
                case "$local_timing" in [0-5]) ;; *)
                    echo -e "${RED}Error:${NC} -T must be 0-5 (got: $local_timing)"; exit 1 ;;
                esac ;;
            --no-web)      local_skip_web=true; shift ;;
            --no-ping)     local_skip_ping=true; shift ;;
            -v|--verbose)     local_verbose=true; shift ;;
            --udp)            local_do_udp=true; shift ;;
            --vuln)           local_do_vuln=true; shift ;;
            --screenshots)    local_do_screenshots=true; shift ;;
            --dns)            local_do_dns=true; shift ;;
            --wordlist)       local_wordlist="$2"; shift 2 ;;
            --fast)           shift ;;  # fast is default, nothing to do
            -h|--help)        show_usage; exit 0 ;;
            --)            shift; break ;;
            -*)            echo -e "${RED}Error:${NC} unknown option: $1"; show_usage; exit 1 ;;
            *)             [ -n "$local_target" ] && echo -e "${YELLOW}Warning:${NC} ignoring extra argument: $1" || local_target="$1"; shift ;;
        esac
    done
    for arg in "$@"; do
        [ -z "$local_target" ] && local_target="$arg"
    done

    if [ -z "$local_target" ]; then
        echo -e "${YELLOW}No target specified.${NC}"
        check_deps
        print_banner
        echo -e "Starting interactive shell..."
        echo ""
        interactive_shell
    else
        check_deps
        print_banner
        if [ -z "$local_outdir" ]; then
            resolved_outdir=$(get_output_dir "$local_target")
        else
            resolved_outdir="$local_outdir"
        fi
        run_scan "$local_target" "$resolved_outdir" "$local_port_range" "$local_timing" "$local_skip_web" "$local_skip_ping" "$local_verbose" "$local_do_udp" "$local_do_vuln" "$local_do_screenshots" "$local_do_dns" "$local_wordlist"
    fi
fi
