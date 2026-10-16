import json
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def analyze_literature():
    with open("research/notes/unified_academic_index.json", "r", encoding="utf-8") as f:
        papers = json.load(f)
        
    taxonomy = {
        "multimodal_fusion": [],
        "static_attachments_macros_pdf": [],
        "urls_typosquatting_homoglyphs": [],
        "explainable_ai_decision_support": [],
        "adversarial_evasion_robustness": [],
        "bec_social_engineering": []
    }
    
    for p in papers:
        text = f"{p.get('title', '')} {p.get('abstract', '')}".lower()
        if any(k in text for k in ["fusion", "multi-channel", "multi-modal", "hybrid"]):
            taxonomy["multimodal_fusion"].append(p["title"])
        if any(k in text for k in ["macro", "pdf", "attachment", "ole", "vba", "static analysis"]):
            taxonomy["static_attachments_macros_pdf"].append(p["title"])
        if any(k in text for k in ["url", "typosquatting", "homoglyph", "homograph", "punycode", "domain"]):
            taxonomy["urls_typosquatting_homoglyphs"].append(p["title"])
        if any(k in text for k in ["explainab", "xai", "transpar", "decision support", "interpretab"]):
            taxonomy["explainable_ai_decision_support"].append(p["title"])
        if any(k in text for k in ["adversarial", "evasion", "robustness", "bypass"]):
            taxonomy["adversarial_evasion_robustness"].append(p["title"])
        if any(k in text for k in ["bec", "business email compromise", "social engineering", "spearphishing"]):
            taxonomy["bec_social_engineering"].append(p["title"])
            
    summary = {
        "total_papers": len(papers),
        "cluster_counts": {k: len(v) for k, v in taxonomy.items()},
        "taxonomy": taxonomy
    }
    
    with open("research/notes/deep_literature_taxonomy.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        
    print(f"[+] Taxonomy compiled across {len(papers)} papers:")
    for k, v in summary["cluster_counts"].items():
        print(f"    - {k}: {v} papers")

if __name__ == '__main__':
    analyze_literature()
