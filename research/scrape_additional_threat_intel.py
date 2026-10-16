import sys
import json
import time
from scrapling import Fetcher

def fetch_threat_intel():
    print("[*] Scrapling: Fetching real-world threat campaigns and CVE references...")
    targets = [
        {
            "name": "CISA_Stop_Ransomware_Phishing",
            "url": "https://www.cisa.gov/stopransomware"
        },
        {
            "name": "MITRE_T1204_User_Execution",
            "url": "https://attack.mitre.org/techniques/T1204/002/"
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
            
    with open("research/industry_reports/real_world_threat_campaigns.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("[+] Saved to research/industry_reports/real_world_threat_campaigns.json")

if __name__ == '__main__':
    fetch_threat_intel()
