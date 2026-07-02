# shellcheck shell=bash
# shellcheck source=../recon.sh

# =============================================================================
# report.sh — self-contained HTML report generator
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
