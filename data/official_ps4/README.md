# PS 4 — Phishing Email, URL and Attachment Risk Checker (sample data)

Synthetic emails (`.eml`), URL/text samples and **inert** attachment fixtures. Two variants: `_A`, `_B`.
All senders use fictional `.example` / `.test` domains; all bodies are short, clearly-marked synthetic samples.

## What participants get

| Path | Purpose |
|------|---------|
| `emails/mission01/M1-01..M1-16_{A,B}.eml` | Mission 01: email + URL analysis; 8 phishing, 8 legitimate (incl. benign invoice/newsletter lookalikes) |
| `emails/mission02/M2-01..M2-14_{A,B}.eml` | Mission 02: attachment analysis — macro docs, PDF active content, double/RLO extensions, type mismatch, encrypted & nested archives + benign attachments |
| `emails/mission04_tests/TC01..TC15_*` | One file per Mission 04 test case |
| `fixtures/` | Standalone copies of every attachment, for direct parser testing |
| `text_samples/url_samples_*`, `pasted_email_bodies_*` | For teams that accept pasted text/URLs instead of `.eml` |
| `reference/email_index_*`, `attachment_index_*` | Inventory of every email and attachment (declared vs detected type, size, SHA-256) |
| `config/checker_config_{A,B}.yaml` | Limits, high-risk extensions, header/URL rules, safety switches |
| `config/known_bad_hashes_{A,B}.csv` | Local hash list (never submit to online scanners) |
| `labels/mission01_email_labels_*` | Ground truth for Mission 01 (self-check) |

## Attachment fixtures — all inert and safe
- **MZ executable stubs** (`.exe`, double-extension `invoice.pdf.exe`, RLO-override name, declared-PDF-but-MZ): start with `MZ` so a magic-byte check detects a PE header; body is a marker comment, **no code**.
- **Macro document** (`.docm`): real macro-enabled container whose `vbaProject.bin` is a placeholder — detectable, **cannot run**.
- **PDF with active content**: carries `/OpenAction` + `/JavaScript` whose JS is a comment only.
- **HTML with password field**: form `action="#"`, submits nowhere.
- **Encrypted ZIP**: password is given in the email body; contents are marker text.
- **Nested ZIP**: 4 layers (exceeds the depth-2 limit); innermost is marker text.
- **Benign**: clean PDFs, plain DOCX, ZIP of PNG images.

## Detection points exercised
Header checks (SPF/DKIM/DMARC from `Authentication-Results`, Reply-To/Return-Path mismatch, display-name
spoof), URL rules (IP-literal, shortener, link-text/href mismatch, lookalike domain), and attachment
rules (high-risk extension, double/RLO extension, extension-MIME-magic mismatch, macros, PDF active
content, HTML credential form, encrypted/nested archives, oversized/corrupt/zero-byte → UNSCANNED/UNKNOWN).

## Safety rules for teams (also in config)
Never execute, render or extract attachments to disk; parse in memory or a temp folder deleted after.
Detect type by magic bytes, not extension. Never upload attachments/hashes to online scanners.

## Answer keys (organiser only)
`ORGANISER_ONLY_Answer_Keys/PS4/` — Mission 02 email labels, attachment labels, Mission 04 expected results.
