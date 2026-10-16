import io
import struct

MAGIC_SIGNATURES = [
    ("Windows PE Executable / DLL / SCR / CPL", b"\x4d\x5a", 0, "application/x-dosexec", [".exe", ".dll", ".scr", ".cpl"]),
    ("ZIP / OOXML / JAR / APK", b"\x50\x4b\x03\x04", 0, "application/zip", [".zip", ".docx", ".xlsx", ".pptx", ".jar"]),
    ("ZIP Empty", b"\x50\x4b\x05\x06", 0, "application/zip", [".zip"]),
    ("ZIP Spanned", b"\x50\x4b\x07\x08", 0, "application/zip", [".zip"]),
    ("OLE Compound Binary (Legacy Office / MSI)", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "application/x-ole-storage", [".doc", ".xls", ".ppt", ".msi"]),
    ("PDF Document", b"\x25\x50\x44\x46", 0, "application/pdf", [".pdf"]),
    ("7-Zip Archive", b"\x37\x7a\xbc\xaf\x27\x1c", 0, "application/x-7z-compressed", [".7z"]),
    ("RAR Archive v4/v5", b"\x52\x61\x72\x21\x1a\x07", 0, "application/x-rar-compressed", [".rar"]),
    ("GZIP Compressed Archive", b"\x1f\x8b", 0, "application/gzip", [".gz", ".tar.gz"]),
    ("Windows Shell Shortcut", b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "application/x-ms-shortcut", [".lnk"]),
    ("RTF Document", b"{\\rtf", 0, "application/rtf", [".rtf"]),
    ("PNG Image", b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 0, "image/png", [".png"]),
    ("JPEG Image", b"\xff\xd8\xff", 0, "image/jpeg", [".jpg", ".jpeg"]),
    ("GIF Image", b"GIF87a", 0, "image/gif", [".gif"]),
    ("GIF Image v89", b"GIF89a", 0, "image/gif", [".gif"]),
]

def detect_magic(buffer: bytes):
    for name, sig, offset, mime, exts in MAGIC_SIGNATURES:
        if len(buffer) >= offset + len(sig):
            if buffer[offset:offset+len(sig)] == sig:
                # Special check for ISO 9660
                return {"type": name, "mime": mime, "valid_extensions": exts, "magic_hex": sig.hex().upper()}
    # Check for ISO at offset 0x8000
    if len(buffer) > 0x8005 and buffer[0x8001:0x8006] == b"CD001":
        return {"type": "ISO 9660 Disk Image", "mime": "application/x-iso9660-image", "valid_extensions": [".iso"], "magic_hex": "CD001"}
    
    # Check text/html/xml
    head = buffer[:512].strip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html") or b"<body" in head:
        return {"type": "HTML Document", "mime": "text/html", "valid_extensions": [".html", ".htm"], "magic_hex": "ASCII-HTML"}
    if head.startswith(b"<?xml"):
        return {"type": "XML Document", "mime": "application/xml", "valid_extensions": [".xml"], "magic_hex": "ASCII-XML"}
        
    return {"type": "Unknown Binary or Plaintext", "mime": "application/octet-stream", "valid_extensions": [], "magic_hex": ""}

if __name__ == '__main__':
    # Test cases
    test_exe = b"MZ\x90\x00\x03\x00\x00\x00"
    test_pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>"
    test_html = b"<!DOCTYPE html><html><body>Login here</body></html>"
    
    print("Test PE:", detect_magic(test_exe))
    print("Test PDF:", detect_magic(test_pdf))
    print("Test HTML:", detect_magic(test_html))
