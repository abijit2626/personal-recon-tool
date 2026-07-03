# Ghost

```text
  ⠀⠀⠀⠀⠀⠀⢀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
  ⠀⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀⠀⠀⢀⣼⡇  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
  ⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⣴⣿⣿⠃ ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
  ⠀⠀⠀⠀⢠⣿⣿⣿⣇⠀⠀⢀⣾⣿⣿⣿⠀ ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ 
  ⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⡟⠀ ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ 
  ⠀⠀⢰⡿⠉⠀⡜⣿⣿⣿⡿⠿⢿⣿⣿⠃⠀  ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   
  ⠒⠒⠸⣿⣄⡘⣃⣿⣿⡟⢰⠃⠀⢹⣿⡇⠀   ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░    
  ⠚⠉⠀⠈⠻⣿⣿⣿⣿⣿⣮⣤⣤⣿⡟⠁⠀ ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░      
  ⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠛⠛⠛⠁⠀⠒⠤       ░  ░  ░  ░    ░ ░        ░           
  ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠀⠀
```                                            

**Automated Bash recon framework for CTFs, HTB, and authorized pentest engagements.**

Ghost takes a target and runs a full recon pipeline — port scan, web fingerprinting, service-specific enumeration, DNS recon, content discovery, SSL/TLS checks, screenshots, and vuln scanning — then generates a self-contained HTML report. One entry point, modular libs, zero prompts, zero overwrites.

> ⚠️ **For authorized use only.** Ghost is built for CTF platforms (HTB, THM), labs, and engagements where you have explicit written permission to test. Running this against systems you don't own or have authorization to test is illegal in most jurisdictions. You are responsible for how you use this tool.

---

## Features

- **Single entry point** — `ghost.sh` sources modular libraries, no manual chaining of tools
- **Two modes** — one-shot (`ghost <target> [flags]`) or an interactive shell with persistent state (`set` / `show` / `scan` / `help` / `exit`)
- **Graceful degradation** — every optional tool is checked with `check_tool()`; missing tools are skipped silently, never fatal
- **Hang-proof** — `run_capped()` wraps every external command with a timeout so one stuck tool doesn't stall the whole run
- **Safe output handling** — runs are written to timestamped, auto-incrementing directories; nothing is ever overwritten
- **Fast by default** — `--fast` (default) skips UDP scanning, vuln scripts, and screenshots for quick first-pass recon

## Pipeline

| # | Stage | What it does |
|---|-------|---------------|
| 1 | **TCP port scan** (`network.sh`) | `nmap -sV -T4`, configurable port range/timing, parses `.gnmap` for open ports |
| 2 | **Web fingerprinting** (inline) | Headers, `<title>` extraction, `robots.txt`, `whatweb` tech detection per HTTP(S) port |
| 3 | **Service enumeration** (`service_enum.sh`) | Dispatches per-port modules — see below |
| 4 | **DNS recon** (`dns_recon.sh`) | A/AAAA/MX/NS/TXT/SOA lookups, AXFR zone transfer attempts, subdomain enum (subfinder/amass/assetfinder, merged + deduped) |
| 5 | **Web content discovery** (`web.sh`) | Dir brute (feroxbuster → gobuster → ffuf fallback), historical URLs (gau → waybackurls), nikto |
| 6 | **SSL/TLS scan** (`network.sh`) | `sslscan` or `nmap ssl-enum-ciphers`/`ssl-heartbleed` on HTTPS ports |
| 7 | **Screenshots** (`screenshot.sh`) | `gowitness` or `aquatone` on discovered web URLs |
| 8 | **NSE vuln scan** (`network.sh`) | `nmap --script vuln`, flags `VULNERABLE` findings |
| 9 | **UDP scan** (`network.sh`) | `nmap` top-50 UDP ports (requires sudo) |
| 10 | **HTML report** (`report.sh`) | Self-contained page: nmap output, service findings, web results, screenshots |

### Service-specific enumeration (stage 3)

| Port | Service | Actions |
|------|---------|---------|
| 21 | FTP | Anonymous login test, `ftp-anon`/`ftp-syst` NSE scripts |
| 22 | SSH | Banner grab, `ssh2-enum-algos`/`hostkey`/`auth-methods` |
| 111 / 135 | RPC | `rpcinfo -p`, `rpc-grind` NSE script |
| 161/udp | SNMP | `onesixtyone` community brute-force, `snmpwalk` |
| 445 | SMB | `enum4linux`, `smbclient` null sessions, `smbmap`, MS17-010 NSE check |
| 3306 | MySQL | Root empty-password test, `mysql-info` NSE script |
| 6379 | Redis | `redis-cli INFO` without auth, key scan |
| 27017 | MongoDB | `mongodb-info` NSE script, `listDatabases` via client |

## Installation

```bash
git clone https://github.com/<your-username>/ghost.git
cd ghost
chmod +x ghost.sh
./ghost.sh --help
```

### Dependencies

**Required:** `nmap`, `curl`

**Optional (auto-detected, skipped if missing):** `whatweb`, `nikto`, `feroxbuster`/`gobuster`/`ffuf`, `enum4linux`, `smbclient`, `smbmap`, `sslscan`, `gowitness`/`aquatone`, `onesixtyone`, `snmpwalk`, `redis-cli`, `mongosh`, `rpcinfo`, `dig`, `subfinder`, `amass`, `assetfinder`, `gau`, `waybackurls`, `ftp`, mysql client

Install what you have — Ghost checks for each tool at runtime and adapts accordingly.

## Usage

### One-shot mode

```bash
ghost 10.10.10.10
ghost example.com --dns
ghost 10.10.10.10 --output /path/to/dir
ghost 10.10.10.10 --full   # includes UDP, vuln scan, screenshots
```

### Interactive mode

```bash
ghost
ghost> set target 10.10.10.10
ghost> set ports 1-10000
ghost> show
ghost> scan
ghost> exit
```

## Output

Results are written to:

```
$HOME/ghost_output/ghost_<target>_<timestamp>/
```

Configurable via `GHOST_HOME` environment variable or `--output` flag. Duplicate runs are auto-renamed with `_2`, `_3`, etc. — nothing is ever prompted or overwritten.

## Flags

| Flag | Description |
|------|-------------|
| `--fast` | Default. Skips UDP scan, NSE vuln scan, and screenshots |
| `--full` | Runs the complete pipeline, including UDP/vuln/screenshots |
| `--dns` | Forces DNS recon module even for IP targets |
| `--output <dir>` | Custom output directory |

## Disclaimer

Ghost is intended for use in CTF competitions, authorized penetration tests, and lab environments (HTB, THM, etc.) where you have explicit permission to test. The author(s) assume no liability for misuse. Always get written authorization before scanning any system you do not own.

## License

MIT (or your preferred license — add a `LICENSE` file to the repo)
