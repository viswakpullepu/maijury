"""
Robust RFC 5322 & MIME Stream Forensic Parser.
Zero-dependency, memory-safe in-memory extractor for headers, body, URLs, and MIME attachments.
"""
import email
from email import policy
import re
import hashlib
from typing import Dict, List, Any, Optional
import os

class EMLParser:
    """Forensic email message parser extracting all protocol layers."""

    @staticmethod
    def parse(raw_input: bytes | str) -> Dict[str, Any]:
        """
        Parses raw email bytes or string into a comprehensive forensic structure.
        """
        if isinstance(raw_input, str):
            raw_bytes = raw_input.encode('utf-8', errors='ignore')
            raw_str = raw_input
        else:
            raw_bytes = raw_input
            raw_str = raw_input.decode('utf-8', errors='ignore')

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)

        # 1. Header Dictionary & Normalization
        headers: Dict[str, Any] = {}
        received_hops: List[str] = []
        auth_results: List[str] = []
        dkim_signatures: List[str] = []

        for k, v in msg.items():
            k_lower = k.lower()
            val_str = str(v)
            if k_lower == 'received':
                received_hops.append(val_str)
            elif k_lower == 'authentication-results':
                auth_results.append(val_str)
            elif k_lower == 'dkim-signature':
                dkim_signatures.append(val_str)
            else:
                headers[k_lower] = val_str

        headers['received'] = received_hops
        headers['authentication-results'] = auth_results
        headers['dkim-signature'] = dkim_signatures

        # Primary fields
        from_header = headers.get('from', '')
        subject_header = headers.get('subject', '')
        to_header = headers.get('to', '')
        date_header = headers.get('date', '')
        message_id = headers.get('message-id', '')
        reply_to = headers.get('reply-to', '')
        return_path = headers.get('return-path', '')

        # Extract From Display Name and Email
        from_display, from_email = EMLParser._extract_name_and_email(from_header)
        reply_to_display, reply_to_email = EMLParser._extract_name_and_email(reply_to)
        return_path_clean = re.sub(r'[<>\s]', '', return_path)

        # 2. Extract Body (Plaintext and HTML)
        body_text_parts: List[str] = []
        body_html_parts: List[str] = []
        attachments: List[Dict[str, Any]] = []

        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                cd = str(part.get('Content-Disposition', ''))
                fn = part.get_filename()

                is_attachment = ('attachment' in cd.lower()) or bool(fn)

                if is_attachment:
                    payload = part.get_payload(decode=True) or b""
                    att_info = EMLParser._parse_attachment_part(part, fn, ct, payload)
                    attachments.append(att_info)
                else:
                    if ct == 'text/plain':
                        try:
                            content = part.get_content()
                            if isinstance(content, str):
                                body_text_parts.append(content)
                        except Exception:
                            payload = part.get_payload(decode=True) or b""
                            body_text_parts.append(payload.decode('utf-8', errors='ignore'))
                    elif ct == 'text/html':
                        try:
                            content = part.get_content()
                            if isinstance(content, str):
                                body_html_parts.append(content)
                        except Exception:
                            payload = part.get_payload(decode=True) or b""
                            body_html_parts.append(payload.decode('utf-8', errors='ignore'))
        else:
            ct = msg.get_content_type()
            try:
                content = msg.get_content()
                if isinstance(content, str):
                    if ct == 'text/html':
                        body_html_parts.append(content)
                    else:
                        body_text_parts.append(content)
            except Exception:
                payload = msg.get_payload(decode=True) or b""
                text = payload.decode('utf-8', errors='ignore')
                if ct == 'text/html':
                    body_html_parts.append(text)
                else:
                    body_text_parts.append(text)

        body_text = "\n".join(body_text_parts)
        body_html = "\n".join(body_html_parts)
        combined_body = body_html if body_html else body_text

        # 3. Extract URLs
        urls = EMLParser._extract_urls(body_html, body_text)

        return {
            "sha256": sha256_hash,
            "raw_str": raw_str,
            "raw_bytes_len": len(raw_bytes),
            "headers": headers,
            "envelope": {
                "from_raw": from_header,
                "from_display": from_display,
                "from_email": from_email,
                "from_domain": from_email.split('@')[-1].lower() if '@' in from_email else "",
                "to": to_header,
                "subject": subject_header,
                "date": date_header,
                "message_id": message_id,
                "reply_to": reply_to_email,
                "reply_to_display": reply_to_display,
                "return_path": return_path_clean,
                "return_path_domain": return_path_clean.split('@')[-1].lower() if '@' in return_path_clean else "",
            },
            "hops": received_hops,
            "auth_results": auth_results,
            "dkim_signatures": dkim_signatures,
            "body": {
                "plain": body_text,
                "html": body_html,
                "combined": combined_body,
                "length": len(combined_body)
            },
            "urls": urls,
            "attachments": attachments
        }

    @staticmethod
    def _extract_name_and_email(header_val: str) -> tuple[str, str]:
        if not header_val:
            return "", ""
        match = re.search(r'^(.*?)\s*<([^>]+)>', header_val.strip())
        if match:
            display = match.group(1).strip().strip('"').strip("'")
            addr = match.group(2).strip().lower()
            return display, addr
        # No angle brackets, might just be email address
        val = header_val.strip().strip('"').strip("'")
        if '@' in val:
            return "", val.lower()
        return val, ""

    @staticmethod
    def _extract_urls(html_content: str, text_content: str) -> List[Dict[str, str]]:
        url_dict: Dict[str, Dict[str, str]] = {}

        # 1. Extract from HTML href
        href_matches = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_content, re.IGNORECASE | re.DOTALL)
        for href, anchor_inner in href_matches:
            clean_href = href.strip()
            # Strip tags from anchor
            anchor_text = re.sub(r'<[^>]+>', '', anchor_inner).strip()
            if clean_href.startswith(('http://', 'https://')):
                url_dict[clean_href] = {
                    "url": clean_href,
                    "anchor_text": anchor_text,
                    "source": "html_href"
                }

        # 2. Extract bare URLs from text and HTML
        combined = f"{html_content}\n{text_content}"
        bare_matches = re.findall(r'https?://[a-zA-Z0-9_\-\.\:\@\%\?\&\=\+\~\#\/]+', combined)
        for u in bare_matches:
            clean_u = u.strip().rstrip('.,;:)"\'>')
            if clean_u not in url_dict:
                url_dict[clean_u] = {
                    "url": clean_u,
                    "anchor_text": clean_u,
                    "source": "text_regex"
                }

        return list(url_dict.values())

    @staticmethod
    def _parse_attachment_part(part, filename: Optional[str], declared_ct: str, payload: bytes) -> Dict[str, Any]:
        fn = filename or "unnamed_attachment"
        ext = os.path.splitext(fn)[1].lower() if '.' in fn else ""
        magic_hex = payload[:16].hex().upper() if payload else ""

        # Quick entropy calculation
        entropy = 0.0
        if payload:
            from collections import Counter
            import math
            counts = Counter(payload)
            total = len(payload)
            for c in counts.values():
                p = c / total
                entropy -= p * math.log2(p)

        return {
            "filename": fn,
            "extension": ext,
            "declared_type": declared_ct,
            "size_bytes": len(payload),
            "magic_hex": magic_hex,
            "first_16_bytes": payload[:16],
            "entropy": round(entropy, 3),
            "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
            "raw_payload": payload
        }
