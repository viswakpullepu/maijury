"""
Scrape Quishing research papers and Palo Alto Unit 42 report using Scrapling
"""
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from scrapling import Fetcher
import os

targets = [
    {
        "name": "arxiv_quishing_ml",
        "url": "https://arxiv.org/html/2505.03451v2"
    },
    {
        "name": "unit42_quishing_report",
        "url": "https://unit42.paloaltonetworks.com/qr-code-phishing/"
    }
]

out_dir = "research/threat_intel"
os.makedirs(out_dir, exist_ok=True)

for t in targets:
    url = t["url"]
    name = t["name"]
    print(f"[*] Fetching {name} ({url}) via Scrapling...")
    try:
        page = Fetcher.get(url, timeout=30)
        print(f"[*] Status: {page.status}")
        md = page.markdown() if hasattr(page, 'markdown') else page.body.decode('utf-8', errors='ignore')
        out_path = os.path.join(out_dir, f"{name}.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[+] Saved {len(md)} chars to {out_path}")
    except Exception as e:
        print(f"[-] Error fetching {name}: {e}")
