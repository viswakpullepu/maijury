import os
import json
import glob
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def build_corpus_synthesis():
    print("[*] Synthesizing research corpus across all collected modules...")
    
    paper_files = glob.glob("research/papers/*.json") + glob.glob("research/benchmarks/*.json")
    industry_files = glob.glob("research/industry_reports/*.json")
    business_files = glob.glob("research/business_journals/*.json")
    evasion_files = glob.glob("research/evasion_mechanics/*.json")
    
    print(f"[+] Found {len(paper_files)} paper index files")
    print(f"[+] Found {len(industry_files)} industry report files")
    print(f"[+] Found {len(business_files)} business journal files")
    print(f"[+] Found {len(evasion_files)} evasion mechanics files")
    
    all_papers = []
    for pf in paper_files:
        try:
            with open(pf, 'r', encoding='utf-8') as f:
                data = json.load(f)
            items = data if isinstance(data, list) else data.get('results', data.get('data', []))
            for item in items:
                if isinstance(item, dict) and 'title' in item:
                    all_papers.append({
                        "file_source": pf,
                        "title": item.get('title'),
                        "id": item.get('id', item.get('doi', '')),
                        "abstract": item.get('abstract', item.get('description', ''))
                    })
        except Exception as e:
            print(f"[-] Error reading {pf}: {e}")
            
    print(f"[+] Total distinct academic papers cataloged: {len(all_papers)}")
    
    # Save unified academic index
    with open("research/notes/unified_academic_index.json", "w", encoding="utf-8") as f:
        json.dump(all_papers, f, indent=2)
        
    print("[+] Saved unified academic index to research/notes/unified_academic_index.json")

if __name__ == '__main__':
    build_corpus_synthesis()
