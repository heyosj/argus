const URGENCY_PATTERNS = [
  /\b(urgent|immediately|asap|right away|act now|limited time)\b/i,
  /\b(expire|suspend|terminate|deactivate|close your account)\b/i,
  /\b(within 24 hours|within 48 hours|today only)\b/i,
  /\b(final notice|last warning|immediate action required)\b/i,
];

const CREDENTIAL_PATTERNS = [
  /\b(verify your|confirm your|update your)\s+(account|password|credentials|identity)\b/i,
  /\b(login|sign in|log in)\s+(here|now|to)\b/i,
  /\b(enter your|provide your)\s+(password|credentials|ssn|social security)\b/i,
  /\b(click here to|click the link|click below)\b/i,
];

const IMPERSONATION_PATTERNS = [
  /\b(paypal|microsoft|apple|amazon|netflix|bank of|wells fargo|chase)\b/i,
  /\b(security team|support team|customer service|help desk)\b/i,
  /\b(official|authorized|verified)\b/i,
];

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'tiny.cc'
];

export function analyzeThreats(email) {
  const indicators = [];
  let score = 0;

  // Check authentication failures
  if (email.authentication.spf_status === 'fail') {
    score += 25;
    indicators.push({
      category: 'Authentication',
      description: 'SPF check failed',
      severity: 'high',
      details: 'The sender\'s domain did not authorize this server to send emails on its behalf.',
    });
  } else if (email.authentication.spf_status === 'softfail') {
    score += 10;
    indicators.push({
      category: 'Authentication',
      description: 'SPF soft fail',
      severity: 'medium',
      details: 'The sender\'s SPF policy indicates this server may not be authorized.',
    });
  }

  if (email.authentication.dkim_status === 'fail') {
    score += 25;
    indicators.push({
      category: 'Authentication',
      description: 'DKIM verification failed',
      severity: 'high',
      details: 'The email\'s DKIM signature could not be verified.',
    });
  }

  if (email.authentication.dmarc_status === 'fail') {
    score += 25;
    indicators.push({
      category: 'Authentication',
      description: 'DMARC check failed',
      severity: 'high',
      details: 'The email failed DMARC policy validation.',
    });
  }

  // Check for Return-Path mismatch
  if (email.return_path && email.from) {
    const fromLower = email.from.toLowerCase();
    const returnPathLower = email.return_path.toLowerCase();
    if (!fromLower.includes(returnPathLower) && !returnPathLower.includes(fromLower)) {
      score += 15;
      indicators.push({
        category: 'Header Anomaly',
        description: 'Return-Path mismatch',
        severity: 'medium',
        details: `From: ${email.from} differs from Return-Path: ${email.return_path}`,
      });
    }
  }

  // Check for Reply-To mismatch
  if (email.reply_to && email.from) {
    const fromLower = email.from.toLowerCase();
    const replyToLower = email.reply_to.toLowerCase();
    if (!fromLower.includes(replyToLower)) {
      score += 15;
      indicators.push({
        category: 'Header Anomaly',
        description: 'Reply-To mismatch',
        severity: 'medium',
        details: `Replies would go to ${email.reply_to} instead of ${email.from}`,
      });
    }
  }

  // Check for urgency language
  const combinedText = `${email.subject} ${email.body_text} ${email.body_html}`;

  for (const pattern of URGENCY_PATTERNS) {
    if (pattern.test(combinedText)) {
      score += 10;
      indicators.push({
        category: 'Social Engineering',
        description: 'Urgency language detected',
        severity: 'medium',
        details: 'The email uses urgent or pressure tactics common in phishing.',
      });
      break;
    }
  }

  // Check for credential harvesting language
  for (const pattern of CREDENTIAL_PATTERNS) {
    if (pattern.test(combinedText)) {
      score += 20;
      indicators.push({
        category: 'Credential Harvesting',
        description: 'Credential request detected',
        severity: 'high',
        details: 'The email contains language requesting login or personal information.',
      });
      break;
    }
  }

  // Check for impersonation attempts
  for (const pattern of IMPERSONATION_PATTERNS) {
    const match = combinedText.match(pattern);
    if (match) {
      const brand = match[0].toLowerCase();
      const fromLower = email.from.toLowerCase();
      if (!fromLower.includes(brand)) {
        score += 15;
        indicators.push({
          category: 'Impersonation',
          description: `Possible ${brand} impersonation`,
          severity: 'high',
          details: `Email mentions ${brand} but sender domain doesn't match.`,
        });
        break;
      }
    }
  }

  // Check for URL shorteners
  for (const url of email.urls) {
    const urlLower = url.toLowerCase();
    for (const shortener of URL_SHORTENERS) {
      if (urlLower.includes(shortener)) {
        score += 10;
        indicators.push({
          category: 'Suspicious URL',
          description: 'URL shortener detected',
          severity: 'medium',
          details: `URL shortener used: ${shortener} (may hide malicious destination)`,
        });
        break;
      }
    }
  }

  // Check for mismatched URL domains
  const fromMatch = email.from.match(/@([^\s>]+)/);
  const fromDomain = fromMatch ? fromMatch[1].toLowerCase() : '';

  for (const url of email.urls) {
    try {
      const parsed = new URL(url);
      const hostLower = parsed.hostname.toLowerCase();
      if (fromDomain && !hostLower.includes(fromDomain) && !fromDomain.includes(hostLower)) {
        score += 5;
        indicators.push({
          category: 'Suspicious URL',
          description: 'External domain in links',
          severity: 'low',
          details: `Link points to ${parsed.hostname} which differs from sender domain`,
        });
        break;
      }
    } catch (e) {}
  }

  // Check for suspicious attachments
  for (const attachment of email.attachments) {
    const ext = attachment.filename.split('.').pop()?.toLowerCase() || '';
    if (['exe', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'msi'].includes(ext)) {
      score += 30;
      indicators.push({
        category: 'Malicious Attachment',
        description: `Dangerous file type: .${ext}`,
        severity: 'high',
        details: `Attachment '${attachment.filename}' is an executable file type`,
      });
    } else if (['zip', 'rar', '7z', 'iso', 'img'].includes(ext)) {
      score += 10;
      indicators.push({
        category: 'Suspicious Attachment',
        description: `Archive file type: .${ext}`,
        severity: 'medium',
        details: `Attachment '${attachment.filename}' is an archive that may contain malware`,
      });
    }
  }

  // Determine threat level
  const level = score >= 50 ? 'High' : score >= 25 ? 'Medium' : 'Low';

  const summary = {
    High: 'This email shows multiple high-risk indicators consistent with phishing or malicious intent.',
    Medium: 'This email shows some suspicious characteristics that warrant caution.',
    Low: 'This email shows minimal suspicious indicators but should still be verified.',
  }[level];

  return {
    level,
    score,
    indicators,
    summary,
  };
}
