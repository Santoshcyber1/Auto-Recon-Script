#!/bin/bash

# Auto Recon Script by Madhav (GitHub-Ready Version)
# Usage: ./recon.sh example.com

domain=$1
if [ -z "$domain" ]; then
  echo "Usage: $0 <target-domain>"
  exit 1
fi

output_dir="$domain-recon"
mkdir -p "$output_dir"/{subdomains,nmap,whois,web,osint}

echo "[*] Starting Recon on: $domain"

# WHOIS
echo "[+] WHOIS Info..."
whois $domain > "$output_dir/whois/whois.txt"

# DNS Info
echo "[+] DNS Info..."
dig $domain any +noall +answer > "$output_dir/whois/dns.txt"
dnsrecon -d $domain -n 8.8.8.8 -a > "$output_dir/whois/dnsrecon.txt"

# Subdomain Enumeration
echo "[+] Subdomain Enumeration..."
subfinder -d $domain -silent > "$output_dir/subdomains/subfinder.txt"
assetfinder --subs-only $domain >> "$output_dir/subdomains/assetfinder.txt"
cat "$output_dir/subdomains/"*.txt | sort -u > "$output_dir/subdomains/all.txt"

# Live Probing
echo "[+] Probing live domains..."
httpx -silent -l "$output_dir/subdomains/all.txt" > "$output_dir/subdomains/live.txt"

# Nmap Scan
cat "$output_dir/subdomains/live.txt" | sed -E 's#https?://##' | cut -d '/' -f1 | sort -u > "$output_dir/nmap/targets.txt"
echo "[+] Running Nmap..."
nmap -iL "$output_dir/nmap/targets.txt" -sS -sV -T4 -Pn -oN "$output_dir/nmap/nmap.txt"
# Directory Brute-forcing
echo "[+] Bruteforcing Directories..."
while read url; do
  short=$(echo $url | cut -d '/' -f3)
  dirsearch -u "$url" -e php,html,txt,json -o "$output_dir/web/$short.txt"
done < "$output_dir/subdomains/live.txt"

# OSINT - theHarvester
echo "[+] Running theHarvester for OSINT..."
theHarvester -d $domain -b google,bing -f "$output_dir/osint/theHarvester.html"

echo "✅ Recon Completed. All results saved to $output_dir/"
