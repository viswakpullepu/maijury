import sys
import json
import time
from scrapling import Fetcher

def fetch_m3aawg_and_standards():
    print("[*] Scrapling: Fetching anti-abuse and authentication standards...")
    targets = [
        {
            "name": "M3AAWG_Email_Auth_Best_Practices",
            "url": "https://www.m3aawg.org/activities/published-documents"
        },
        {
            "name": "BIMI_Group_Overview",
            "url": "https://bimigroup.org/all-about-bimi/"
        },
        {
            "name": "ARC_Specification_RFC8617",
            "url": "https://datatracker.ietf.org/doc/html/rfc8617"
        }
    ]
    
    results = {}
    for target in targets:
        print(f"[*] Fetching {target['name']} from {target['url']}...")
        try:
            page = Fetcher.get(target['url'], timeout=15)
            title = page.css("title::text").first.text if page.css("title::text") else target['name']
            paragraphs = page.css("p, li")
            text = "\n\n".join([p.text for p in paragraphs[:12] if len(p.text.strip()) > 30])
            results[target['name']] = {
                "title": title.strip(),
                "url": target['url'],
                "content": text[:3500]
            }
            print(f"[+] Scraped {target['name']} ({len(text)} chars)")
            time.sleep(1)
        except Exception as e:
            print(f"[-] Error fetching {target['name']}: {e}")
            results[target['name']] = {"error": str(e), "url": target['url']}
            
    with open("research/rfc_standards/m3aawg_and_bimi.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("[+] Saved to research/rfc_standards/m3aawg_and_bimi.json")

if __name__ == '__main__':
    fetch_m3aawg_and_standards()
