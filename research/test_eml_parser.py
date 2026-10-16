import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import hashlib
import io
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Local offline hash list (harmless demonstration hashes of known threat families)
LOCAL_KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty File (Zero Bytes)",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Known Emotet Dropper Template",
    "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a": "Known Qakbot Word Macro Template"
}

def create_synthetic_phish_eml():
    msg = MIMEMultipart()
    msg['From'] = '"Corporate IT Admin <support@global-corp.com>" <helpdesk-alert@external-cloud.com>'
    msg['To'] = 'victim.employee@global-corp.com'
    msg['Reply-To'] = 'security-response@freemail-host.org'
    msg['Return-Path'] = '<bounce-42@mass-spammer.info>'
    msg['Subject'] = 'URGENT: Microsoft 365 Password Expires in 2 Hours'
    msg['Authentication-Results'] = 'mx.global-corp.com; spf=softfail; dkim=fail; dmarc=fail'
    
    body = """
    <html>
    <body>
    <p>Dear Employee,</p>
    <p>Your corporate password expires today. Please verify your credentials immediately to avoid suspension:
       <a href="http://192.168.1.105/auth/login">https://login.microsoftonline.com/auth</a>
    </p>
    <p>Please inspect the attached report for your pending service tickets.</p>
    </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html'))
    
    # Attachment 1: Disguised double-extension executable
    att1 = MIMEBase('application', 'pdf')
    att1.set_payload(b"MZ\x90\x00FakePEHeaderBytesForStaticTesting")
    encoders.encode_base64(att1)
    att1.add_header('Content-Disposition', 'attachment', filename='Urgent_Security_Report.pdf.exe')
    msg.attach(att1)
    
    # Attachment 2: Active PDF with /JavaScript
    att2 = MIMEBase('application', 'pdf')
    att2.set_payload(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n2 0 obj\n<< /S /JavaScript /JS (app.alert('pwned');) >>\nendobj\n%%EOF")
    encoders.encode_base64(att2)
    att2.add_header('Content-Disposition', 'attachment', filename='Invoice_Scanned.pdf')
    msg.attach(att2)
    
    return msg.as_string()

def parse_and_inventory_eml(eml_string: str):
    msg = email.message_from_string(eml_string)
    
    inventory = []
    for part in msg.walk():
        if part.is_multipart():
            continue
            
        filename = part.get_filename()
        content_type = part.get_content_type()
        
        # If it has a filename or is an attachment disposition
        disp = str(part.get("Content-Disposition", ""))
        if filename or "attachment" in disp.lower():
            payload = part.get_payload(decode=True) or b""
            sha256 = hashlib.sha256(payload).hexdigest()
            size = len(payload)
            
            # Local hash match check
            known_threat = LOCAL_KNOWN_MALICIOUS_HASHES.get(sha256, None)
            
            inventory.append({
                "filename": filename or "unnamed_attachment",
                "declared_type": content_type,
                "size_bytes": size,
                "sha256": sha256,
                "known_local_threat": known_threat,
                "payload_preview_hex": payload[:16].hex()
            })
            
    return inventory

if __name__ == '__main__':
    raw_eml = create_synthetic_phish_eml()
    inv = parse_and_inventory_eml(raw_eml)
    print(f"[EML Parser Test] Extracted {len(inv)} attachments:")
    for item in inv:
        print(f"  - File: {item['filename']} | Declared: {item['declared_type']} | Size: {item['size_bytes']} bytes")
        print(f"    SHA-256: {item['sha256']}")
        print(f"    Hex Preview: {item['payload_preview_hex']}")
        print(f"    Local Hash Hit: {item['known_local_threat']}\n")
