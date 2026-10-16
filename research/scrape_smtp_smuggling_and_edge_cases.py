import sys
import json
import time
from scrapling import Fetcher

def fetch_smtp_smuggling_and_advanced_spoofing():
    print("[*] Scrapling: Fetching research on SMTP Smuggling and advanced spoofing attacks...")
    targets = [
        {
            "name": "SEC_Consult_SMTP_Smuggling",
            "url": "https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/"
        },
        {
            "name": "Cisco_Talos_SMTP_Smuggling",
            "url": "https://blog.talosintelligence.com/smtp-smuggling/"
        }
    ]
    
    results = {}
    for target in targets:
        print(f"[*] Fetching {target['name']} from {target['url']}...")
        try:
            page = Fetcher.get(target['url'], timeout=15)
            title = page.css("title::text").first.text if page.css("title::text") else target['name']
            paragraphs = page.css("p")
            text = "\n\n".join([p.text for p in paragraphs[:12] if len(p.text.strip()) > 30])
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
            
    with open("research/threat_intel/smtp_smuggling_research.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("[+] Saved to research/threat_intel/smtp_smuggling_research.json")

if __name__ == '__main__':
    fetch_smtp_smuggling_and_advanced_spoofing()
