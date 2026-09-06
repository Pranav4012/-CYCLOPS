#!/usr/bin/env bash
# Fetch the REAL datasets CYCLOPS trains/evaluates its DGA model on.
# Sources are public. Re-run to refresh.
set -e
cd "$(dirname "$0")"
echo "downloading DGA dataset (chrmor/DGA_domains_dataset, ~20MB, 25 real families + Alexa legit)..."
curl -sSL --max-time 120 "https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains_full.csv" -o dga_domains_full.csv
echo "downloading OpenDNS top-10k benign domains..."
curl -sSL --max-time 60 "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt" -o opendns-top-domains.txt
echo "done: $(wc -l < dga_domains_full.csv) DGA rows, $(wc -l < opendns-top-domains.txt) benign"
