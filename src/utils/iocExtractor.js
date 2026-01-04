export function defangUrl(url) {
  return url
    .replace(/http:\/\//gi, 'hxxp://')
    .replace(/https:\/\//gi, 'hxxps://')
    .replace(/\./g, '[.]');
}

export function defangDomain(domain) {
  return domain.replace(/\./g, '[.]');
}

export function defangEmail(email) {
  return email.replace('@', '[@]').replace(/\./g, '[.]');
}

export function defangIp(ip) {
  return ip.replace(/\./g, '[.]');
}

export function extractIOCs(email) {
  const defangedDomains = email.domains.map(d => defangDomain(d));
  const defangedUrls = email.urls.map(u => defangUrl(u));
  const defangedIps = email.ip_addresses.map(ip => defangIp(ip));
  const defangedEmails = email.email_addresses.map(e => defangEmail(e));

  const fileHashes = email.attachments.map(a => ({
    filename: a.filename,
    sha256: a.sha256,
  }));

  const headersOfInterest = [];

  email.headers.forEach(header => {
    const nameLower = header.name.toLowerCase();

    if (nameLower === 'x-originating-ip') {
      headersOfInterest.push({
        name: header.name,
        value: header.value,
        reason: 'Source IP of the email sender',
      });
    }

    if (nameLower === 'x-mailer') {
      headersOfInterest.push({
        name: header.name,
        value: header.value,
        reason: 'Email client used to send the message',
      });
    }

    if (nameLower === 'received' && header.value.toLowerCase().includes('from')) {
      if (headersOfInterest.filter(h => h.name.toLowerCase() === 'received').length < 3) {
        headersOfInterest.push({
          name: header.name,
          value: header.value,
          reason: 'Email routing information',
        });
      }
    }
  });

  if (email.from && email.return_path) {
    const fromLower = email.from.toLowerCase();
    const returnPathLower = email.return_path.toLowerCase();
    if (!fromLower.includes(returnPathLower) && !returnPathLower.includes(fromLower)) {
      headersOfInterest.push({
        name: 'Return-Path Mismatch',
        value: `From: ${email.from} | Return-Path: ${email.return_path}`,
        reason: 'Return-Path does not match From address - possible spoofing',
      });
    }
  }

  if (email.reply_to && email.from) {
    const fromLower = email.from.toLowerCase();
    const replyToLower = email.reply_to.toLowerCase();
    if (!fromLower.includes(replyToLower)) {
      headersOfInterest.push({
        name: 'Reply-To Mismatch',
        value: `From: ${email.from} | Reply-To: ${email.reply_to}`,
        reason: 'Reply-To does not match From address - possible redirect',
      });
    }
  }

  headersOfInterest.push({
    name: 'SPF',
    value: email.authentication.spf_status,
    reason: 'SPF validation result',
  });

  headersOfInterest.push({
    name: 'DKIM',
    value: email.authentication.dkim_status,
    reason: 'DKIM validation result',
  });

  headersOfInterest.push({
    name: 'DMARC',
    value: email.authentication.dmarc_status,
    reason: 'DMARC validation result',
  });

  return {
    domains: defangedDomains,
    urls: defangedUrls,
    ip_addresses: defangedIps,
    email_addresses: defangedEmails,
    file_hashes: fileHashes,
    headers_of_interest: headersOfInterest,
  };
}

export function formatIOCsForCopy(iocs) {
  let output = '';

  if (iocs.domains.length > 0) {
    output += '## Domains\n';
    iocs.domains.forEach(d => output += `- ${d}\n`);
    output += '\n';
  }

  if (iocs.urls.length > 0) {
    output += '## URLs\n';
    iocs.urls.forEach(u => output += `- ${u}\n`);
    output += '\n';
  }

  if (iocs.ip_addresses.length > 0) {
    output += '## IP Addresses\n';
    iocs.ip_addresses.forEach(ip => output += `- ${ip}\n`);
    output += '\n';
  }

  if (iocs.email_addresses.length > 0) {
    output += '## Email Addresses\n';
    iocs.email_addresses.forEach(e => output += `- ${e}\n`);
    output += '\n';
  }

  if (iocs.file_hashes.length > 0) {
    output += '## File Hashes\n';
    iocs.file_hashes.forEach(h => output += `- ${h.filename}: SHA256: ${h.sha256}\n`);
    output += '\n';
  }

  if (iocs.headers_of_interest.length > 0) {
    output += '## Headers of Interest\n';
    iocs.headers_of_interest.forEach(h => output += `- ${h.name}: ${h.value}\n`);
  }

  return output;
}
