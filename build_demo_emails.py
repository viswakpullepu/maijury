"""
GENERATE SEPARATE STANDALONE DEMO EML FILES FOR MISSION 02
Creates 5 realistic .eml files with full MIME structures, real byte headers, and attachments.
"""
import os
import io
import zipfile
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def create_demo_emails():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(root_dir, "demo_emails")
    os.makedirs(out_dir, exist_ok=True)

    print(f"Generating separate demo email files in: {out_dir}")

    # ─────────────────────────────────────────────────────────────────────────
    # 1. SCAM: Renamed Executable (.pdf containing MZ DOS/PE header)
    # ─────────────────────────────────────────────────────────────────────────
    msg1 = MIMEMultipart()
    msg1["Subject"] = "URGENT: Legal Court Notice of Impending Foreclosure - Immediate Response Required"
    msg1["From"] = '"Judicial Enforcement Office" <legal-notice@summons-enforcement-court.com>'
    msg1["To"] = "employee@target-corp.com"
    msg1["Date"] = "Wed, 16 Oct 2026 14:10:00 +0530"
    msg1["Authentication-Results"] = "mx.google.com; spf=fail; dkim=fail; dmarc=fail"

    body1 = (
        "CONFIDENTIAL LEGAL NOTICE\n\n"
        "You are hereby served notice regarding case #CR-984102-2026.\n"
        "Immediate appearance or response is mandatory within 24 hours to avoid a bench warrant.\n"
        "Please review the attached official court summons PDF immediately.\n\n"
        "Office of the Clerk of the Court\n"
        "State Judicial Center"
    )
    msg1.attach(MIMEText(body1, "plain"))

    # MZ Windows PE payload disguised as PDF
    mz_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"
    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + (b"\x00" * 32)
    fake_exe_bytes = mz_header + dos_stub + b"\x50\x45\x00\x00\x4c\x01\x01\x00" + (b"\x90" * 128)

    part1 = MIMEBase("application", "pdf")
    part1.set_payload(fake_exe_bytes)
    encoders.encode_base64(part1)
    part1.add_header("Content-Disposition", 'attachment; filename="Official_Court_Summons_Notice.pdf"')
    msg1.attach(part1)

    f1_path = os.path.join(out_dir, "01_SCAM_disguised_exe_in_pdf.eml")
    with open(f1_path, "wb") as f:
        f.write(msg1.as_bytes())
    print("  [+] Created 01_SCAM_disguised_exe_in_pdf.eml")

    # ─────────────────────────────────────────────────────────────────────────
    # 2. SCAM: Weaponized Macro Document (.docm with vbaProject.bin)
    # ─────────────────────────────────────────────────────────────────────────
    msg2 = MIMEMultipart()
    msg2["Subject"] = "OVERDUE INVOICE #INV-49219 - Final Demand Before Legal Action"
    msg2["From"] = '"Acme Corporate Billing" <accounts-receivable@supplier-portal-payments.com>'
    msg2["To"] = "finance@target-corp.com"
    msg2["Date"] = "Wed, 16 Oct 2026 14:15:00 +0530"
    msg2["Authentication-Results"] = "mx.google.com; spf=softfail; dkim=none; dmarc=fail"

    body2 = (
        "Dear Accounts Payable,\n\n"
        "Your payment for Invoice #INV-49219 ($48,250.00) is now 45 days past due.\n"
        "Please open the attached Word invoice and enable content/macros to view the digitally certified cryptographic payment authorization slip.\n\n"
        "Failure to remit funds by 5:00 PM will trigger credit reporting.\n\n"
        "Regards,\n"
        "Collections Department"
    )
    msg2.attach(MIMEText(body2, "plain"))

    # Construct genuine OOXML container with vbaProject.bin
    buf2 = io.BytesIO()
    with zipfile.ZipFile(buf2, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>')
        zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Enable Macros to verify remittance slip</w:t></w:r></w:p></w:body></w:document>')
        zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"AutoOpen Sub AutoOpen() Shell('cmd.exe') End Sub")
    docm_bytes = buf2.getvalue()

    part2 = MIMEBase("application", "vnd.ms-word.document.macroEnabled.12")
    part2.set_payload(docm_bytes)
    encoders.encode_base64(part2)
    part2.add_header("Content-Disposition", 'attachment; filename="Overdue_Invoice_INV49219.docm"')
    msg2.attach(part2)

    f2_path = os.path.join(out_dir, "02_SCAM_macro_word_doc.eml")
    with open(f2_path, "wb") as f:
        f.write(msg2.as_bytes())
    print("  [+] Created 02_SCAM_macro_word_doc.eml")

    # ─────────────────────────────────────────────────────────────────────────
    # 3. SCAM: Password-Protected ZIP with In-Body Decryption Password
    # ─────────────────────────────────────────────────────────────────────────
    msg3 = MIMEMultipart()
    msg3["Subject"] = "STRICTLY CONFIDENTIAL: Executive Salary Adjustments & Q1 Bonus Matrix"
    msg3["From"] = '"Human Resources Payroll" <hr-confidential@global-payroll-portal.com>'
    msg3["To"] = "executive@target-corp.com"
    msg3["Date"] = "Wed, 16 Oct 2026 14:20:00 +0530"
    msg3["Authentication-Results"] = "mx.google.com; spf=fail; dkim=none; dmarc=fail"

    body3 = (
        "Dear Colleague,\n\n"
        "Attached is the encrypted payroll spreadsheet containing the approved Q1 executive compensation and bonus adjustments.\n\n"
        "To comply with corporate privacy guidelines, this archive is password protected.\n"
        "Your archive extraction password is: Payroll#2026!Bonus\n\n"
        "Please extract and review your details immediately.\n\n"
        "Corporate Compensation Committee"
    )
    msg3.attach(MIMEText(body3, "plain"))

    # Construct genuine encrypted ZIP with PKWARE general purpose bit 0 flag set
    header_sig = b"PK\x03\x04"
    version = b"\x14\x00"
    flags = b"\x01\x00"  # Bit 0 set = Password encrypted
    compression = b"\x00\x00"
    mod_time = b"\x00\x00\x00\x00"
    crc32 = b"\x12\x34\x56\x78"
    c_size = b"\x10\x00\x00\x00"
    u_size = b"\x10\x00\x00\x00"
    fn = b"Executive_Bonus_2026.xlsx.exe"
    fn_len = len(fn).to_bytes(2, "little")
    extra_len = b"\x00\x00"
    encrypted_payload = b"\xeb\xfe\x90\x90\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66"

    cd_sig = b"PK\x01\x02"
    cd_record = cd_sig + b"\x14\x00" + version + flags + compression + mod_time + crc32 + c_size + u_size + fn_len + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + fn
    eocd = b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00" + len(cd_record).to_bytes(4, "little") + (len(header_sig + version + flags + compression + mod_time + crc32 + c_size + u_size + fn_len + extra_len + fn + encrypted_payload)).to_bytes(4, "little") + b"\x00\x00"

    encrypted_zip_bytes = header_sig + version + flags + compression + mod_time + crc32 + c_size + u_size + fn_len + extra_len + fn + encrypted_payload + cd_record + eocd

    part3 = MIMEBase("application", "zip")
    part3.set_payload(encrypted_zip_bytes)
    encoders.encode_base64(part3)
    part3.add_header("Content-Disposition", 'attachment; filename="Executive_Bonus_Matrix.zip"')
    msg3.attach(part3)

    f3_path = os.path.join(out_dir, "03_SCAM_encrypted_zip_body_password.eml")
    with open(f3_path, "wb") as f:
        f.write(msg3.as_bytes())
    print("  [+] Created 03_SCAM_encrypted_zip_body_password.eml")

    # ─────────────────────────────────────────────────────────────────────────
    # 4. LEGITIMATE: Genuine Vendor PDF Invoice
    # ─────────────────────────────────────────────────────────────────────────
    msg4 = MIMEMultipart()
    msg4["Subject"] = "Invoice #INV-88912 from Cloudflare Enterprise Services"
    msg4["From"] = '"Cloudflare Billing Department" <billing@cloudflare.com>'
    msg4["To"] = "billing-admin@target-corp.com"
    msg4["Date"] = "Wed, 16 Oct 2026 14:25:00 +0530"
    msg4["Authentication-Results"] = "mx.google.com; spf=pass (google.com: domain of billing@cloudflare.com designates 198.41.128.5); dkim=pass header.i=@cloudflare.com; dmarc=pass"

    body4 = (
        "Dear Customer,\n\n"
        "Thank you for choosing Cloudflare Enterprise Services.\n"
        "Attached is your monthly billing statement for Invoice #INV-88912 covering period Oct 1 - Oct 31, 2026.\n"
        "Your account on file will be automatically charged on October 25, 2026.\n\n"
        "For billing inquiries or questions, contact support@cloudflare.com.\n\n"
        "Best regards,\n"
        "Cloudflare Financial Operations Team"
    )
    msg4.attach(MIMEText(body4, "plain"))

    # Valid, clean PDF 1.4 byte structure
    clean_pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << >> /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000056 00000 n \n0000000111 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n198\n%%EOF"
    )

    part4 = MIMEBase("application", "pdf")
    part4.set_payload(clean_pdf_bytes)
    encoders.encode_base64(part4)
    part4.add_header("Content-Disposition", 'attachment; filename="Cloudflare_Invoice_INV88912.pdf"')
    msg4.attach(part4)

    f4_path = os.path.join(out_dir, "04_LEGIT_clean_vendor_invoice.eml")
    with open(f4_path, "wb") as f:
        f.write(msg4.as_bytes())
    print("  [+] Created 04_LEGIT_clean_vendor_invoice.eml")

    # ─────────────────────────────────────────────────────────────────────────
    # 5. LEGITIMATE: Urgent HR Benefits Notice with Long Benign Single-Sign-On URL
    # ─────────────────────────────────────────────────────────────────────────
    msg5 = MIMEMultipart()
    msg5["Subject"] = "URGENT: Mandatory 2026 Annual Health Benefits Open Enrollment Closes Today"
    msg5["From"] = '"Corporate Human Resources" <hr-benefits@company.internal>'
    msg5["To"] = "all-staff@company.internal"
    msg5["Date"] = "Wed, 16 Oct 2026 14:30:00 +0530"
    msg5["Authentication-Results"] = "mx.google.com; spf=pass (google.com: domain of hr-benefits@company.internal designates 10.0.1.50); dkim=pass header.i=@company.internal; dmarc=pass"

    body5 = (
        "ATTENTION ALL EMPLOYEES: IMMEDIATE ACTION REQUIRED BY 5:00 PM TODAY\n\n"
        "This is your final notice regarding the mandatory 2026 Annual Health Benefits Open Enrollment.\n"
        "If you do not complete your enrollment verification today, your current medical and dental elections will default to basic coverage.\n\n"
        "Please click the secure corporate single-sign-on link below to confirm your elections:\n"
        "https://intranet.company.internal/identity/auth/saml2/sso?idp_entity_id=https%3A%2F%2Fokta.company.internal%2Fapp%2Fsso&session_state=b8a92f019c4d8e72a1&target_relay_state=https%3A%2F%2Fbenefits.portal.company.internal%2Fannual-enrollment%2F2026%2Femployee-selection-confirmation%3Fdepartment_code%3DENG%26location%3DUS-WEST\n\n"
        "Attached is the official 2026 Benefits Guidebook for your reference.\n\n"
        "Corporate People & Culture Department"
    )
    msg5.attach(MIMEText(body5, "plain"))

    # Valid clean DOCX file devoid of macros
    buf5 = io.BytesIO()
    with zipfile.ZipFile(buf5, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Official 2026 Employee Benefits Guidebook - Corporate People and Culture</w:t></w:r></w:p></w:body></w:document>')
    clean_docx_bytes = buf5.getvalue()

    part5 = MIMEBase("application", "vnd.openxmlformats-officedocument.wordprocessingml.document")
    part5.set_payload(clean_docx_bytes)
    encoders.encode_base64(part5)
    part5.add_header("Content-Disposition", 'attachment; filename="2026_Benefits_Guidebook.docx"')
    msg5.attach(part5)

    f5_path = os.path.join(out_dir, "05_LEGIT_urgent_hr_benefits_review.eml")
    with open(f5_path, "wb") as f:
        f.write(msg5.as_bytes())
    print("  [+] Created 05_LEGIT_urgent_hr_benefits_review.eml")

    print("\n[SUCCESS] All 5 standalone demo emails created successfully!")
    return out_dir

if __name__ == "__main__":
    create_demo_emails()
