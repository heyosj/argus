# Argus

**Argus** is a client-side email analysis and investigation tool designed for security practitioners, blue teamers, and analysts.

It focuses on **rapid triage of suspicious emails** by parsing raw `.eml` files directly in the browser — no server-side processing, no uploads, no data exfiltration.

Functionally, it mirrors and extends the email investigation workflow found on **heyosj.com**, with room to grow into deeper attachment and threat analysis.

---

## What Argus Does

Argus analyzes raw email files (`.eml`) and extracts:

- Email metadata (From, To, Subject, Date, Return-Path, Reply-To)
- Full headers with readable formatting
- Authentication results (SPF, DKIM, DMARC)
- Email body (original + redacted view)
- Indicators of compromise (IOCs):
  - URLs
  - Domains
  - IP addresses
  - Email addresses
- Attachments:
  - Metadata (filename, MIME type, size, SHA256)
  - Safe, sandboxed **in-browser preview** for supported types (PDF, text)
- Threat signals and behavioral indicators:
  - Social engineering cues
  - Credential harvesting patterns
  - Suspicious URLs and domains

All processing happens **locally in the browser**.

---

## Why Client-Side?

- No email data leaves the analyst’s machine
- No backend to trust or maintain
- Ideal for:
  - Quick investigations
  - Sensitive samples
  - Personal labs / demos
  - Teaching and learning email analysis

---

## Attachment Preview (Important)

Argus supports **sandboxed, read-only previews** for certain attachment types (e.g. PDFs, text files) using the browser’s built-in renderers.

> Previewing does **not** mean the attachment is safe.  
> It only means the file format is valid enough to render without execution.

- No files are executed
- No external applications are launched
- Links inside previews should be treated as untrusted

This mirrors how many professional SOC tools handle attachment triage.

---

## Supported Input

- Drag-and-drop `.eml` files
- File picker upload (`.eml`)
- Paste raw email source (headers + body)

> `.msg` (Outlook) files are not currently supported.

---

## Tech Stack

- **Vite**
- **React**
- **Tailwind CSS**
- **PostalMime** (email parsing)
- Pure browser APIs (no backend)

---

## Current Limitations

- No server-side sandboxing
- No attachment detonation or behavioral analysis
- PDF analysis is visual only (no JS extraction yet)
- No persistence beyond the current session

These are intentional tradeoffs for simplicity and safety.

---

## Roadmap (Planned / Ideas)

- PDF metadata and embedded URL extraction
- Attachment risk classification (renderable vs high-risk)
- Clearer analyst warnings per attachment type
- Exportable investigation reports
- Optional sandbox integrations (future)
- Improved phishing heuristics and scoring

---

## Disclaimer

Argus is an **analysis aid**, not a malware sandbox.

Do not:
- Open attachments natively outside a VM
- Click links without proper isolation
- Assume previewed content is safe

Use proper security hygiene.

---

## About

Argus is a personal security project inspired by real-world email investigation workflows and tooling.

More improvements will be made once it’s publicly hosted and iterated on.

