export function exportMarkdown(result) {
  const threatEmoji = {
    High: '🔴',
    Medium: '🟡',
    Low: '🟢',
  }[result.threat.level];

  let md = `# ${result.email.subject} Analysis

**Analysis Date:** ${result.analyzed_at}
**Threat Level:** ${threatEmoji} ${result.threat.level}

## Summary

${result.threat.summary}

## Email Details

| Field | Value |
|-------|-------|
| From | ${result.email.from} |
| To | ${result.email.to} |
| Subject | ${result.email.subject} |
| Date | ${result.email.date || 'Unknown'} |
| Reply-To | ${result.email.reply_to || 'Not specified'} |
| Return-Path | ${result.email.return_path || 'Not specified'} |

## Authentication Results

| Check | Status |
|-------|--------|
| SPF | ${result.email.authentication.spf_status.toUpperCase()} |
| DKIM | ${result.email.authentication.dkim_status.toUpperCase()} |
| DMARC | ${result.email.authentication.dmarc_status.toUpperCase()} |

`;

  if (result.threat.indicators.length > 0) {
    md += '## Threat Indicators\n\n';
    result.threat.indicators.forEach(indicator => {
      const severityEmoji = indicator.severity === 'high' ? '🔴' : indicator.severity === 'medium' ? '🟡' : '🟢';
      md += `- ${severityEmoji} **${indicator.category}**: ${indicator.description}\n`;
      if (indicator.details) {
        md += `  - ${indicator.details}\n`;
      }
    });
    md += '\n';
  }

  md += '## Indicators of Compromise\n\n';

  if (result.iocs.domains.length > 0) {
    md += '### Domains\n';
    result.iocs.domains.forEach(d => md += `- ${d}\n`);
    md += '\n';
  }

  if (result.iocs.urls.length > 0) {
    md += '### URLs\n';
    result.iocs.urls.forEach(u => md += `- ${u}\n`);
    md += '\n';
  }

  if (result.iocs.ip_addresses.length > 0) {
    md += '### IP Addresses\n';
    result.iocs.ip_addresses.forEach(ip => md += `- ${ip}\n`);
    md += '\n';
  }

  if (result.iocs.email_addresses.length > 0) {
    md += '### Email Addresses\n';
    result.iocs.email_addresses.forEach(e => md += `- ${e}\n`);
    md += '\n';
  }

  if (result.iocs.file_hashes.length > 0) {
    md += '### File Hashes\n';
    result.iocs.file_hashes.forEach(h => md += `- ${h.filename}: SHA256: ${h.sha256}\n`);
    md += '\n';
  }

  if (result.iocs.headers_of_interest.length > 0) {
    md += '### Headers of Interest\n';
    result.iocs.headers_of_interest.forEach(h => md += `- ${h.name}: ${h.value}\n`);
    md += '\n';
  }

  md += '## Email Body (Redacted)\n\n';
  md += '```\n';
  md += result.redaction.redacted_text;
  md += '\n```\n';

  return md;
}

export function exportJSON(result) {
  return JSON.stringify(result, null, 2);
}

export function exportSanitizedEml(result) {
  let sanitized = result.email.raw_content;

  result.redaction.redactions.forEach(redaction => {
    sanitized = sanitized.split(redaction.original).join(redaction.redacted);
  });

  return sanitized;
}

export function downloadFile(content, filename, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
