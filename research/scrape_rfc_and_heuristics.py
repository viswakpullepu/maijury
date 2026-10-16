import sys
import json
import time
from scrapling import Fetcher

def fetch_rfc_and_auth_specs():
    print("[*] Scrapling: Fetching RFC 8601 Authentication-Results specification...")
    targets = [
        {
            "name": "RFC_8601_Auth_Results",
            "url": "https://datatracker.ietf.org/doc/html/rfc8601"
        },
        {
            "name": "DMARC_Org_Overview",
            "url": "https://dmarc.org/overview/"
        }
    ]
    
    results = {}
    for target in targets:
        print(f"[*] Fetching {target['name']} from {target['url']}...")
        try:
            page = Fetcher.get(target['url'], timeout=15)
            title = page.css("title::text").first.text if page.css("title::text") else target['name']
            paragraphs = page.css("p, pre")
            text = "\n\n".join([p.text for p in paragraphs[:15] if len(p.text.strip()) > 40])
            results[target['name']] = {
                "title": title.strip(),
                "url": target['url'],
                "content": text[:4000]
            }
            print(f"[+] Scraped {target['name']} ({len(text)} chars)")
            time.sleep(1)
        except Exception as e:
            print(f"[-] Error fetching {target['name']}: {e}")
            results[target['name']] = {"error": str(e), "url": target['url']}
            
    with open("research/industry_reports/rfc8601_auth_specs.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("[+] Saved to research/industry_reports/rfc8601_auth_specs.json")

if __name__ == '__main__':
    fetch_rfc_and_auth_specs()
