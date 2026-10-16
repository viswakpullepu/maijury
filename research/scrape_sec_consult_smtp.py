"""
Scrape SEC Consult SMTP Smuggling writeup using Scrapling
"""
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from scrapling import Fetcher
import os

url = "https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/"
print(f"[*] Fetching {url} with Scrapling...")

try:
    page = Fetcher.get(url, timeout=30)
    print(f"[*] Status: {page.status}")
    title = page.css("title::text").first.text if page.css("title::text") else "No title"
    print(f"[*] Page Title: {title}")
    
    # Extract article content
    content_els = page.css("article, main, .content, .blog-detail, body")
    main_text = ""
    for el in content_els:
        t = el.text
        if len(t) > len(main_text):
            main_text = t
            
    out_dir = "research/threat_intel"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "sec_consult_smtp_smuggling.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"Source URL: {url}\nTitle: {title}\n\n{main_text}")
    print(f"[+] Saved {len(main_text)} characters to {out_path}")

except Exception as e:
    print(f"[-] Scrapling fetch error: {e}")
