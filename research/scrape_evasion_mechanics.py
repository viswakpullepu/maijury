import sys
import json
import time
from scrapling import Fetcher

def fetch_evasion_sources():
    print("[*] Scrapling: Fetching technical deep dives on evasion vectors...")
    targets = [
        {
            "name": "SANS_HTML_Smuggling",
            "url": "https://www.sans.org/blog/html-smuggling-explained/"
        },
        {
            "name": "BleepingComputer_RTLO",
            "url": "https://www.bleepingcomputer.com/news/security/hackers-use-clever-unicode-trick-to-hide-malicious-executables/"
        },
        {
            "name": "CISA_Phishing_Infographic",
            "url": "https://www.cisa.gov/resources-tools/resources/phishing-infographic"
        }
    ]
    
    results = {}
    for target in targets:
        print(f"[*] Fetching {target['name']} from {target['url']}...")
        try:
            page = Fetcher.get(target['url'], timeout=15)
            title = page.css("title::text").first.text if page.css("title::text") else target['name']
            paragraphs = page.css("p")
            text = "\n\n".join([p.text for p in paragraphs[:8] if len(p.text.strip()) > 30])
            results[target['name']] = {
                "title": title.strip(),
                "url": target['url'],
                "content": text[:3000]
            }
            print(f"[+] Scraped {target['name']} ({len(text)} chars)")
            time.sleep(1)
        except Exception as e:
            print(f"[-] Error fetching {target['name']}: {e}")
            results[target['name']] = {"error": str(e), "url": target['url']}
            
    with open("research/evasion_mechanics/attachment_evasion_mechanics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("[+] Saved to research/evasion_mechanics/attachment_evasion_mechanics.json")

if __name__ == '__main__':
    fetch_evasion_sources()
