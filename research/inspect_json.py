import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def inspect_file(filepath):
    print(f"=== Inspecting {filepath} ===")
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict):
        if 'data' in data and isinstance(data['data'], list):
            items = data['data']
        elif 'data' in data and isinstance(data['data'], dict):
            items = data['data'].get('web', []) or [data['data']]
        elif 'results' in data and isinstance(data['results'], list):
            items = data['results']
        else:
            items = list(data.values())
    else:
        items = data
    print(f"Total entries: {len(items)}")
    for idx, item in enumerate(items[:10]):
        if isinstance(item, dict):
            title = item.get('title', item.get('url', 'No Title'))
            paper_id = item.get('id', item.get('doi', ''))
            categories = item.get('categories', [])
            print(f"[{idx+1}] {title} | ID: {paper_id}")
            abstract = item.get('abstract', item.get('description', item.get('markdown', '')))
            if abstract:
                print(f"    Content: {abstract[:200]}...\n")
        else:
            print(f"[{idx+1}] {str(item)[:100]}")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        inspect_file(sys.argv[1])
