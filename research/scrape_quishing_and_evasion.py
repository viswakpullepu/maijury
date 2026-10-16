import sys
import json
import time
from scrapling import Fetcher

def fetch_quishing_and_advanced_evasion():
    print("[*] Scrapling: Fetching research on Quishing and SVG/Attachment evasion...")
    targets = [
        {
            "name": "BleepingComputer_Quishing",
            "url": "https://www.bleepingcomputer.com/news/security/major-energy-firm-targeted-in-qr-code-phishing-attack/"
        },
        {
            "name": "DarkReading_Quishing_Surge",
            "url": "https://www.darkreading.com/threat-intelligence/qr-code-phishing-attacks-surge-quishing"
        }
    ]
    
    results = {}
    for target in targets:
        print(f"[*] Fetching {target['name']} from {target['url']}...")
        try:
            page = Fetcher.get(target['url'], timeout=15)
            title = page.css("title::text").first.text if page.css("title::text") else target['name']
            paragraphs = page.css("p")
            text = "\n\n".join([p.text for p in paragraphs[:10] if len(p.text.strip()) > 30])
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
            
    with open("research/threat_intel/quishing_and_evasion.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("[+] Saved to research/threat_intel/quishing_and_evasion.json")

if __name__ == '__main__':
    fetch_quishing_and_advanced_evasion()
