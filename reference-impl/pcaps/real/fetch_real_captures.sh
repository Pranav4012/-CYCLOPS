#!/usr/bin/env bash
# Fetch the REAL, public attack captures CYCLOPS is validated against.
# Every threat class in PS 26145 is covered by a genuinely-real capture.
# Sources are public research/threat-intel repositories (cited below).
set -e
cd "$(dirname "$0")"

echo "[1/4] real DDoS captures — StopDDoS/packet-captures (real one-way DDoS traffic)"
SD="https://raw.githubusercontent.com/StopDDoS/packet-captures/main"
for f in pkt.TCP.synflood.spoofed.pcap amp.TCP.reflection.SYNACK.pcap \
         amp.UDP.isakmp.pcap amp.UDP.DNSANY.pcap; do
  curl -sSL --max-time 120 "$SD/$f" -o "$f"
done

echo "[2/4] real DNS tunnels — ggyggy666/DNS-Tunnel-Datasets (iodine, dnscat2)"
DT="https://raw.githubusercontent.com/ggyggy666/DNS-Tunnel-Datasets/main/tunnel"
for f in iodine-cname.pcap dnscat2-txt.pcap; do
  curl -sSL --max-time 120 "$DT/$f" -o "$f"
done

echo "[3/4] real Slowloris — abastin99/PCAP_files"
curl -sSL --max-time 90 "https://raw.githubusercontent.com/abastin99/PCAP_files/main/http_slowloris.pcap" -o http_slowloris.pcap

echo "[4/4] real Cobalt Strike C2 beacon — malware-traffic-analysis.net (2021-05-13)"
echo "      NOTE: password-protected (scheme: infected_YYYYMMDD). Needs 7z or pyzipper (pip install pyzipper)."
curl -sSL --max-time 180 -A "Mozilla/5.0" \
  "https://www.malware-traffic-analysis.net/2021/05/13/2021-05-13-Hancitor-traffic-with-Ficker-Stealer-and-Cobalt-Strike.pcap.zip" \
  -o cobaltstrike.pcap.zip || echo "      (MTA download failed — skip; other 5 classes still cover real data)"
if [ -f cobaltstrike.pcap.zip ]; then
  python3 -c "import pyzipper;\
z=pyzipper.AESZipFile('cobaltstrike.pcap.zip');z.setpassword(b'infected_20210513');z.extractall();print('  extracted')" \
    && mv "2021-05-13-Hancitor-traffic-with-Ficker-Stealer-and-Cobalt-Strike.pcap" cobaltstrike-hancitor.pcap \
    && rm -f cobaltstrike.pcap.zip || echo "      (extract needs: pip install pyzipper)"
fi

echo "done. validate with:  python3 -m eval.validate_real"
