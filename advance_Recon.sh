#!/bin/bash

# ✅ Usage: ./recon.sh <domain>
# 📁 Output: Fast, multi-threaded recon & vuln testing

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
OUTPUT="$DOMAIN-recon"
mkdir -p "$OUTPUT"/{whois,subdomains,nmap,web,osint,logs}
cd "$OUTPUT" || exit 1

log() {
    echo "[$(date +"%H:%M:%S")] $1" | tee -a logs/run.log
}

# -------------------------------
# Passive Recon (WHOIS + DNS)
# -------------------------------
log "Running WHOIS lookup..."
whois $DOMAIN > whois/whois.txt &

log "Collecting DNS info..."
dig $DOMAIN any +noall +answer > whois/dns.txt &
host $DOMAIN >> whois/dns.txt &
wait

# -------------------------------
# Subdomain Enumeration
# -------------------------------
log "Enumerating subdomains..."
(subfinder -d $DOMAIN -silent > subdomains/subfinder.txt &)
(assetfinder --subs-only $DOMAIN >> subdomains/assetfinder.txt &)
wait

cat subdomains/*.txt | sort -u > subdomains/all.txt

# -------------------------------
# Probe Live Subdomains
# -------------------------------
log "Probing live subdomains..."
httpx -silent -l subdomains/all.txt -threads 100 > subdomains/live.txt

# -------------------------------
# Nmap Scan
# -------------------------------
log "Preparing targets for Nmap..."
cat subdomains/live.txt | sed -E 's#https?://##' | cut -d '/' -f1 | sort -u > nmap/targets.txt
nmap -iL nmap/targets.txt -sS -sV -T4 -Pn -oN nmap/nmap.txt &

# -------------------------------
# Directory Bruteforce (Parallel)
# -------------------------------
log "Running dirsearch scans in parallel..."
cat subdomains/live.txt | xargs -P 10 -I % bash -c 'short=$(echo % | cut -d "/" -f3); dirsearch -u % -e php,html,txt,json -o web/$short.txt' &

# -------------------------------
# OSINT
# -------------------------------
log "Running theHarvester (OSINT)..."
theHarvester -d $DOMAIN -b bing,duckduckgo -f osint/theHarvester.html &

# -------------------------------
# URL Collection (Wayback + Gau + Hakrawler + Waymore)
# -------------------------------
log "Collecting URLs (multi-source)..."
(waybackurls "$DOMAIN" > wayback.txt &)
(gau "$DOMAIN" > gau.txt &)
(hakrawler -url https://$DOMAIN -depth 2 -plain >> hakrawler.txt &)
(waymore -u https://$DOMAIN -o waymore.txt &)
wait

log "Filtering non-static URLs..."
cat wayback.txt gau.txt hakrawler.txt waymore.txt 2>/dev/null | \
  egrep -v '\.(gif|js|css|html|png|jpeg|jpg|pdf|svg|ico|woff|ttf|eot|mp4|webp|txt|xml)$' | \
  sort -u | tee unique_directories.txt

grep "=" unique_directories.txt > param_urls.txt

# -------------------------------
# Vulnerability Categorization
# -------------------------------
log "Classifying URLs by vuln type..."
gf xss param_urls.txt > possible_xss.txt
gf sqli param_urls.txt > possible_sqli.txt
gf rce param_urls.txt > possible_rce.txt
gf redirect param_urls.txt > possible_redirect.txt
gf lfi param_urls.txt > possible_lfi.txt

# -------------------------------
# Dalfox, SQLMap, Commix, OpenRedireX (Parallel)
# -------------------------------
if [ -s possible_xss.txt ]; then
    log "Running Dalfox..."
    dalfox file possible_xss.txt -o xss_poc.txt &
fi

if [ -s possible_sqli.txt ]; then
    log "Running SQLMap..."
    sqlmap -m possible_sqli.txt --batch --output-dir=sqlmap_results &
fi

if [ -s possible_rce.txt ]; then
    log "Running Commix (RCE)..."
    cat possible_rce.txt | xargs -P 5 -I % bash -c 'commix --url % --batch --level 3 --output-dir=commix_results' &
fi

if [ -s possible_redirect.txt ]; then
    log "Running OpenRedireX..."
    openredirex -l possible_redirect.txt -p payloads.txt -o openredirex_results.txt &
fi

# -------------------------------
# Nuclei Scan
# -------------------------------
if [ -s unique_directories.txt ]; then
    log "Running Nuclei..."
    nuclei -l unique_directories.txt -t ~/nuclei-templates/ -o nuclei_results.txt &
fi

# -------------------------------
# JS Endpoints
# -------------------------------
log "Extracting JS Endpoints..."
cat unique_directories.txt | grep ".js" | httpx -silent -mc 200 -threads 50 -o js_files.txt
cat js_files.txt | xargs -n 1 -P 10 -I % bash -c "curl -s % | linkfinder -i stdin -o cli" >> js_endpoints.txt &

wait
log "Recon and vulnerability scanning complete for $DOMAIN ✅"
echo "[+] All data saved in: $(pwd)"
