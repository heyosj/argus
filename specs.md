# Project Prview - Phishing Email Analyzer

## Project Overview
Build a desktop application called "Prview" for analyzing phishing emails locally with automatic redaction and IOC extraction. The goal is to give security researchers a tool to safely analyze and share phishing attempts.

## Tech Stack
- **Framework**: Tauri (Rust backend for security/performance)
- **Frontend**: React with Tailwind CSS
- **Processing**: 100% local, no network calls except optional user-provided API keys
- **Package Manager**: npm/yarn

## Core Requirements

### 1. Email Import
- Drag and drop support for .eml and .msg files
- Paste raw email source option
- Store recent analyses locally (last 10-20)
- Display recent analyses with threat level indicators

### 2. Email Parsing
Required data extraction:
- Full email headers (From, To, Subject, Return-Path, Reply-To, etc.)
- SPF, DKIM, DMARC validation results
- Email body (HTML and plain text)
- All URLs (extract and defang)
- All domains
- IP addresses from headers
- Attachment metadata (filename, size, SHA256 hash - do NOT store actual files)
- Timestamps

Libraries to consider:
- Rust: `mailparse` crate for .eml parsing
- URL extraction and defanging
- Header parsing with authentication result extraction

### 3. Automatic Redaction
Auto-detect and redact:
- Email addresses (replace with ███████@domain or [REDACTED])
- Phone numbers (all common formats)
- Credit card numbers
- Social security numbers
- Personal names (when detected in common patterns like "Dear [Name]")
- Custom redaction patterns user can define

Manual redaction:
- Click and drag to highlight text for redaction
- Right-click menu option "Redact Selection"
- Preview redacted vs original with toggle

### 4. Analysis Features
Generate threat assessment:
- Overall threat level (High/Medium/Low) based on:
  - SPF/DKIM/DMARC failures
  - Suspicious URLs (mismatched domains, shorteners, new domains)
  - Urgency language detection
  - Impersonation attempts
  - Credential harvesting indicators

Display clearly:
- Authentication results with color coding (red=fail, amber=soft fail, green=pass)
- Suspicious indicators with explanations
- URL destinations (follow redirects, show final destination)
- Domain age and registration info (optional, requires API)

### 5. IOC Extraction
Automatically compile:
- All domains (defanged: example[.]com)
- All URLs (defanged: hxxps://example[.]com/path)
- IP addresses
- Email addresses (sender, reply-to, return-path)
- File hashes (SHA256 of attachments)
- Headers of interest (X-Originating-IP, Return-Path mismatches, etc.)

Format for easy copy/paste into threat intel platforms.

### 6. Export Functionality
Three export formats:

**Markdown Report** (.md):
```markdown
# [Email Subject] Analysis

**Analysis Date:** [Date]
**Threat Level:** [High/Medium/Low]

## Summary
[Brief description of the phishing attempt]

## Indicators of Compromise

### Domains
- domain1[.]com
- domain2[.]net

### URLs
- hxxps://domain1[.]com/path

### IP Addresses
- 1.2.3.4

### Email Addresses
- sender: attacker@domain[.]com
- reply-to: different@domain[.]com

### File Hashes
- filename.pdf: SHA256: abc123...

### Headers of Interest
- X-Originating-IP: 1.2.3.4
- SPF: FAIL
- DKIM: FAIL

## Technical Analysis
[Detailed findings]

## Email Body (Redacted)
[Redacted email content]
```

**JSON Export** (.json):
- Structured data for programmatic use
- All parsed fields
- IOCs in arrays
- Redaction map

**Sanitized Email** (.eml):
- Original email with all PII redacted
- Safe to share with colleagues

### 7. UI Design Specifications
Reference the mockup artifact for exact design. Key specs:

**Colors:**
- Background: slate-900 (#0f172a)
- Secondary bg: slate-950 (#020617)
- Cards: slate-800/50 with transparency
- Accent: cyan-500 (#06b6d4)
- Text primary: slate-100
- Text secondary: slate-400
- Borders: slate-700/slate-800
- Threat indicators: red-400 (high), amber-400 (medium), green-400 (low)

**Typography:**
- UI text: Default sans-serif
- Technical data (headers, IOCs, code): Monospace font
- Headers: font-semibold
- Body: font-normal

**Layout:**
- Max width: 7xl (1280px) centered
- Padding: 6 (1.5rem) on sides, 8 (2rem) vertical
- Card spacing: gap-6
- Rounded corners: rounded-lg (0.5rem) or rounded-xl (0.75rem)

**Components:**
- Header with Prview branding (Eye icon) and nav
- Drag/drop zone with dashed border, hover state
- Recent analyses list with threat indicators
- Analysis view with threat level banner
- Grid layout for headers and IOC preview
- Export format cards with icons

### 8. Technical Implementation Notes

**Security Considerations:**
- Never store API keys in code
- Validate all file inputs before parsing
- Sandbox email rendering (don't execute scripts)
- Hash attachments, never store actual files
- Clear sensitive data from memory when done

**Performance:**
- Parse emails asynchronously
- Show loading states for large files
- Cache recent analyses
- Lazy load analysis history

**Error Handling:**
- Graceful failures for malformed emails
- Clear error messages
- Log parsing errors for debugging
- Don't crash on unexpected formats

## Development Phases

### Phase 1 - MVP (Start Here)
1. Project scaffolding (Tauri + React + Tailwind)
2. Basic UI with three views (Import, Analysis, Export)
3. .eml file parsing (headers, body, URLs)
4. Basic auto-redaction (emails, phones)
5. Markdown export with IOC section
6. Local storage for recent analyses

### Phase 2 - Enhanced Features
1. Manual redaction tool
2. .msg file support
3. Authentication result parsing (SPF/DKIM/DMARC)
4. Threat level assessment
5. JSON and sanitized .eml export
6. URL defanging and analysis

### Phase 3 - Advanced
1. Optional API integrations (VirusTotal, URLhaus)
2. Custom redaction patterns
3. Domain age lookup
4. Settings page with API key management
5. Export templates customization

## File Structure
```
prview/
├── src-tauri/          # Rust backend
│   ├── src/
│   │   ├── main.rs
│   │   ├── email_parser.rs
│   │   ├── redactor.rs
│   │   └── ioc_extractor.rs
│   └── Cargo.toml
├── src/                # React frontend
│   ├── components/
│   │   ├── Header.jsx
│   │   ├── ImportView.jsx
│   │   ├── AnalysisView.jsx
│   │   ├── ExportView.jsx
│   │   └── RecentAnalyses.jsx
│   ├── App.jsx
│   └── main.jsx
├── package.json
└── README.md
```

## Success Criteria
- Can import and parse .eml files
- Automatically redacts PII
- Extracts and defangs IOCs
- Exports clean Markdown report
- Professional security tool aesthetic
- Runs entirely locally, no data leaves machine

## Design Reference
The UI mockup has been created showing all three views (Import, Analysis, Export). Use this as the visual reference for component structure, spacing, colors, and interactions. The mockup demonstrates the complete user flow and styling standards.
