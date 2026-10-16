import sys
import json
import time
from scrapling import Fetcher

def fetch_attack_info():
    print("[*] Scrapling: Fetching MITRE ATT&CK T1566 and T1027.006...")
    targets = [
        {
            "name": "MITRE_T1566_Phishing",
            "url": "https://attack.mitre.org/techniques/T1566/"
        },
        {
            "name": "MITRE_T1027_006_HTML_Smuggling",
            "url": "https://attack.mitre.org/techniques/T1027/006/"
        },
        {
            "name": "MITRE_T1036_002_Right_to_Left_Override",
            "url": "https://attack.mitre.org/techniques/T1036/002/"
        }
    ]
    
    results = {}
    for target in targets:
        print(f"[*] Fetching {target['name']} from {target['url']}...")
        try:
            page = Fetcher.get(target['url'], timeout=15)
            # Extract main description and mitigation/detection
            title = page.css("title::text").first.text if page.css("title::text") else target['name']
            # extract text from description divs
            desc_elements = page.css(".description-body p")
            desc_text = "\n\n".join([el.text for el in desc_elements[:5]])
            
            # extract detection elements if available
            det_elements = page.css("#detection p")
            det_text = "\n\n".join([el.text for el in det_elements[:3]])
            
            results[target['name']] = {
                "title": title.strip(),
                "url": target['url'],
                "description": desc_text,
                "detection": det_text
            }
            print(f"[+] Successfully scraped {target['name']} ({len(desc_text)} chars)")
            time.sleep(1)
        except Exception as e:
            print(f"[-] Error fetching {target['name']}: {e}")
            results[target['name']] = {"error": str(e), "url": target['url']}
            
    with open("research/industry_reports/mitre_attack_tactics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("[+] Saved to research/industry_reports/mitre_attack_tactics.json")

if __name__ == '__main__':
    fetch_attack_info()
