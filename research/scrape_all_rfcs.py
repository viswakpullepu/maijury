import sys
import json
import time
from scrapling import Fetcher

def fetch_all_rfcs():
    print("[*] Scrapling: Fetching canonical RFC email standards...")
    rfcs = [
        {"name": "RFC_7208_SPF", "url": "https://datatracker.ietf.org/doc/html/rfc7208"},
        {"name": "RFC_6376_DKIM", "url": "https://datatracker.ietf.org/doc/html/rfc6376"},
        {"name": "RFC_7489_DMARC", "url": "https://datatracker.ietf.org/doc/html/rfc7489"},
        {"name": "RFC_8617_ARC", "url": "https://datatracker.ietf.org/doc/html/rfc8617"},
        {"name": "RFC_8461_MTA_STS", "url": "https://datatracker.ietf.org/doc/html/rfc8461"},
        {"name": "RFC_7672_DANE", "url": "https://datatracker.ietf.org/doc/html/rfc7672"},
        {"name": "RFC_8601_Auth_Results", "url": "https://datatracker.ietf.org/doc/html/rfc8601"}
    ]
    
    rfc_database = {}
    for rfc in rfcs:
        print(f"[*] Fetching {rfc['name']} from {rfc['url']}...")
        try:
            page = Fetcher.get(rfc['url'], timeout=15)
            title = page.css("title::text").first.text if page.css("title::text") else rfc['name']
            # extract text from pre and p elements
            text_blocks = [el.text for el in page.css("p, pre") if len(el.text.strip()) > 50]
            summary_text = "\n\n".join(text_blocks[:8])
            rfc_database[rfc['name']] = {
                "title": title.strip(),
                "url": rfc['url'],
                "summary": summary_text[:3500]
            }
            print(f"[+] Scraped {rfc['name']} ({len(summary_text)} chars)")
            time.sleep(1)
        except Exception as e:
            print(f"[-] Error fetching {rfc['name']}: {e}")
            rfc_database[rfc['name']] = {"error": str(e), "url": rfc['url']}
            
    with open("research/rfc_standards/complete_rfc_database.json", "w", encoding="utf-8") as f:
        json.dump(rfc_database, f, indent=2)
    print("[+] Successfully saved to research/rfc_standards/complete_rfc_database.json")

if __name__ == '__main__':
    fetch_all_rfcs()
