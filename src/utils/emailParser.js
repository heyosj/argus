// src/utils/emailParser.js
import PostalMime from "postal-mime";

const URL_REGEX = /https?:\/\/[^\s<>"'\)}\]>]+/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
const IP_REGEX =
  /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
const DOMAIN_REGEX =
  /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/gi;

function generateId(content) {
  const s = typeof content === "string" ? content : "";
  let hash = 0;
  for (let i = 0; i < s.length; i++) {
    const char = s.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).substring(0, 16);
}

function extractHeader(headers, name) {
  const header = headers.find((h) => h.key.toLowerCase() === name.toLowerCase());
  return header ? header.value : null;
}

function parseAuthenticationResults(headers) {
  const authResults = extractHeader(headers, "authentication-results") || "";
  const receivedSpf = extractHeader(headers, "received-spf") || "";
  const dkimSignature = extractHeader(headers, "dkim-signature");

  const spfStatus = (() => {
    const combined = (authResults + " " + receivedSpf).toLowerCase();
    if (
      combined.includes("spf=pass") ||
      (receivedSpf.toLowerCase().includes("pass") && !receivedSpf.toLowerCase().includes("fail"))
    )
      return "pass";
    if (combined.includes("spf=fail") || receivedSpf.toLowerCase().includes("fail")) return "fail";
    if (combined.includes("spf=softfail") || receivedSpf.toLowerCase().includes("softfail"))
      return "softfail";
    if (combined.includes("spf=neutral") || receivedSpf.toLowerCase().includes("neutral"))
      return "neutral";
    return "unknown";
  })();

  const dkimStatus = (() => {
    const lower = authResults.toLowerCase();
    if (lower.includes("dkim=pass")) return "pass";
    if (lower.includes("dkim=fail")) return "fail";
    if (dkimSignature) return "present";
    return "unknown";
  })();

  const dmarcStatus = (() => {
    const lower = authResults.toLowerCase();
    if (lower.includes("dmarc=pass")) return "pass";
    if (lower.includes("dmarc=fail")) return "fail";
    if (lower.includes("dmarc=none")) return "none";
    return "unknown";
  })();

  return {
    spf: receivedSpf || null,
    dkim: dkimSignature || null,
    dmarc: authResults || null,
    spf_status: spfStatus,
    dkim_status: dkimStatus,
    dmarc_status: dmarcStatus,
  };
}

function extractUrls(text, html) {
  const urls = new Set();

  (text.match(URL_REGEX) || []).forEach((url) => urls.add(url.replace(/[.,)\]>;]+$/, "")));
  (html.match(URL_REGEX) || []).forEach((url) => urls.add(url.replace(/[.,)\]>;]+$/, "")));

  const hrefRegex = /href=["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(html)) !== null) {
    if (match[1].startsWith("http")) urls.add(match[1]);
  }

  return Array.from(urls);
}

function extractDomains(urls, text) {
  const domains = new Set();

  urls.forEach((urlStr) => {
    try {
      const url = new URL(urlStr);
      domains.add(url.hostname.toLowerCase());
    } catch {
      // ignore
    }
  });

  (text.match(DOMAIN_REGEX) || []).forEach((domain) => {
    const lower = domain.toLowerCase();
    if (
      !lower.endsWith(".png") &&
      !lower.endsWith(".jpg") &&
      !lower.endsWith(".gif") &&
      !lower.endsWith(".css")
    ) {
      domains.add(lower);
    }
  });

  return Array.from(domains);
}

function extractIps(headers) {
  const ips = new Set();

  headers.forEach((header) => {
    (header.value.match(IP_REGEX) || []).forEach((ip) => {
      if (
        !ip.startsWith("10.") &&
        !ip.startsWith("192.168.") &&
        !ip.startsWith("127.") &&
        !ip.startsWith("0.")
      ) {
        ips.add(ip);
      }
    });
  });

  return Array.from(ips);
}

function extractEmailAddresses(text, headers) {
  const emails = new Set();

  (text.match(EMAIL_REGEX) || []).forEach((email) => emails.add(email.toLowerCase()));
  headers.forEach((header) => {
    (header.value.match(EMAIL_REGEX) || []).forEach((email) => emails.add(email.toLowerCase()));
  });

  return Array.from(emails);
}

async function hashAttachment(dataUint8) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", dataUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function base64ToUint8Array(base64) {
  const clean = base64.replace(/\s/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function normalizeToUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (typeof input === "string") return new TextEncoder().encode(input);
  return new TextEncoder().encode(String(input ?? ""));
}

function normalizeAttachmentContent(att) {
  if (att?.content instanceof Uint8Array) return att.content;
  if (att?.content instanceof ArrayBuffer) return new Uint8Array(att.content);

  // Some parsers provide base64 strings
  if (typeof att?.content === "string") {
    try {
      return base64ToUint8Array(att.content);
    } catch {
      return new TextEncoder().encode(att.content);
    }
  }

  // e.g. { buffer: ArrayBuffer }
  if (att?.content?.buffer instanceof ArrayBuffer) return new Uint8Array(att.content.buffer);

  return new Uint8Array();
}

function isLikelyPdf(contentType, filename) {
  const ct = (contentType || "").toLowerCase();
  const fn = (filename || "").toLowerCase();
  return ct.includes("pdf") || fn.endsWith(".pdf");
}

function validatePdfHeader(bytes) {
  // PDF must start with "%PDF-"
  if (!bytes || bytes.byteLength < 5) return false;
  const head = new TextDecoder().decode(bytes.slice(0, 5));
  return head === "%PDF-";
}

export async function parseEmail(content) {
  const parser = new PostalMime();

  // ✅ Parse bytes for reliable attachment decoding
  const rawBytes = normalizeToUint8Array(content);
  const parsed = await parser.parse(rawBytes);

  const headers = (parsed.headers || []).map((h) => ({
    name: h.key,
    value: h.value,
  }));

  const bodyText = parsed.text || "";
  const bodyHtml = parsed.html || "";

  const attachments = await Promise.all(
    (parsed.attachments || []).map(async (att) => {
      const bytes = normalizeAttachmentContent(att);
      const contentType = att.mimeType || "application/octet-stream";
      const filename = att.filename || "unknown";

      const sha256 = await hashAttachment(bytes);
      const blob = new Blob([bytes], { type: contentType });

      // ✅ Stronger UX: detect “PDF that isn't really a PDF”
      let preview_error = null;
      if (isLikelyPdf(contentType, filename) && !validatePdfHeader(bytes)) {
        preview_error =
          "Attachment is labeled PDF but does not contain a valid PDF header (%PDF-). " +
          "Bytes may be truncated or decoded incorrectly.";
      }

      return {
        filename,
        content_type: contentType,
        size: bytes.byteLength,
        sha256,
        blob,
        preview_error,
      };
    })
  );

  const authentication = parseAuthenticationResults(parsed.headers || []);
  const urls = extractUrls(bodyText, bodyHtml);
  const domains = extractDomains(urls, bodyText);
  const ip_addresses = extractIps(parsed.headers || []);
  const email_addresses = extractEmailAddresses(bodyText, parsed.headers || []);

  return {
    id: generateId(typeof content === "string" ? content : ""),
    subject: parsed.subject || "",
    from: parsed.from?.address
      ? `${parsed.from.name || ""} <${parsed.from.address}>`.trim()
      : "",
    to: parsed.to?.map((t) => t.address).join(", ") || "",
    reply_to: parsed.replyTo?.map((r) => r.address).join(", ") || null,
    return_path: extractHeader(parsed.headers || [], "return-path"),
    date: parsed.date ? new Date(parsed.date).toISOString() : null,
    headers,
    body_text: bodyText,
    body_html: bodyHtml,
    urls,
    domains,
    ip_addresses,
    email_addresses,
    attachments,
    authentication,
    raw_content: content,
  };
}
