use mailparse::{parse_mail, MailHeaderMap, ParsedMail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use once_cell::sync::Lazy;

static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"https?://[^\s<>"'\)}\]>]+"#).unwrap()
});

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#).unwrap()
});

static IP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#).unwrap()
});

static DOMAIN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"#).unwrap()
});

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EmailHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub size: usize,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticationResult {
    pub spf: Option<String>,
    pub dkim: Option<String>,
    pub dmarc: Option<String>,
    pub spf_status: String,
    pub dkim_status: String,
    pub dmarc_status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ParsedEmail {
    pub id: String,
    pub subject: String,
    pub from: String,
    pub to: String,
    pub reply_to: Option<String>,
    pub return_path: Option<String>,
    pub date: Option<String>,
    pub headers: Vec<EmailHeader>,
    pub body_text: String,
    pub body_html: String,
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub email_addresses: Vec<String>,
    pub attachments: Vec<Attachment>,
    pub authentication: AuthenticationResult,
    pub raw_content: String,
}

fn extract_header(mail: &ParsedMail, name: &str) -> Option<String> {
    mail.headers.get_first_value(name)
}

fn parse_authentication_results(mail: &ParsedMail) -> AuthenticationResult {
    let auth_results = extract_header(mail, "Authentication-Results").unwrap_or_default();
    let received_spf = extract_header(mail, "Received-SPF").unwrap_or_default();
    let dkim_signature = extract_header(mail, "DKIM-Signature");

    let spf_status = if auth_results.to_lowercase().contains("spf=pass") || received_spf.to_lowercase().contains("pass") {
        "pass".to_string()
    } else if auth_results.to_lowercase().contains("spf=fail") || received_spf.to_lowercase().contains("fail") {
        "fail".to_string()
    } else if auth_results.to_lowercase().contains("spf=softfail") || received_spf.to_lowercase().contains("softfail") {
        "softfail".to_string()
    } else if auth_results.to_lowercase().contains("spf=neutral") || received_spf.to_lowercase().contains("neutral") {
        "neutral".to_string()
    } else {
        "unknown".to_string()
    };

    let dkim_status = if auth_results.to_lowercase().contains("dkim=pass") {
        "pass".to_string()
    } else if auth_results.to_lowercase().contains("dkim=fail") {
        "fail".to_string()
    } else if dkim_signature.is_some() {
        "present".to_string()
    } else {
        "unknown".to_string()
    };

    let dmarc_status = if auth_results.to_lowercase().contains("dmarc=pass") {
        "pass".to_string()
    } else if auth_results.to_lowercase().contains("dmarc=fail") {
        "fail".to_string()
    } else if auth_results.to_lowercase().contains("dmarc=none") {
        "none".to_string()
    } else {
        "unknown".to_string()
    };

    AuthenticationResult {
        spf: Some(received_spf).filter(|s| !s.is_empty()),
        dkim: dkim_signature,
        dmarc: Some(auth_results.clone()).filter(|s| !s.is_empty()),
        spf_status,
        dkim_status,
        dmarc_status,
    }
}

fn extract_body_parts(mail: &ParsedMail) -> (String, String) {
    let mut text_body = String::new();
    let mut html_body = String::new();

    fn process_part(part: &ParsedMail, text: &mut String, html: &mut String) {
        let content_type = part.ctype.mimetype.to_lowercase();

        if content_type.starts_with("multipart/") {
            for subpart in &part.subparts {
                process_part(subpart, text, html);
            }
        } else if content_type == "text/plain" {
            if let Ok(body) = part.get_body() {
                *text = body;
            }
        } else if content_type == "text/html" {
            if let Ok(body) = part.get_body() {
                *html = body;
            }
        }
    }

    process_part(mail, &mut text_body, &mut html_body);

    if text_body.is_empty() && !html_body.is_empty() {
        text_body = strip_html(&html_body);
    }

    (text_body, html_body)
}

fn strip_html(html: &str) -> String {
    let tag_regex = Regex::new(r"<[^>]+>").unwrap();
    let result = tag_regex.replace_all(html, " ");
    let whitespace_regex = Regex::new(r"\s+").unwrap();
    whitespace_regex.replace_all(&result, " ").trim().to_string()
}

fn extract_attachments(mail: &ParsedMail) -> Vec<Attachment> {
    let mut attachments = Vec::new();

    fn process_part(part: &ParsedMail, attachments: &mut Vec<Attachment>) {
        let content_type = part.ctype.mimetype.to_lowercase();

        if content_type.starts_with("multipart/") {
            for subpart in &part.subparts {
                process_part(subpart, attachments);
            }
        } else {
            let disposition = part.headers.get_first_value("Content-Disposition").unwrap_or_default();
            if disposition.contains("attachment") ||
               (!content_type.starts_with("text/") && !content_type.starts_with("multipart/")) {
                if let Ok(body) = part.get_body_raw() {
                    let filename = part.ctype.params.get("name")
                        .cloned()
                        .or_else(|| {
                            let re = Regex::new(r#"filename="?([^";\s]+)"?"#).unwrap();
                            re.captures(&disposition).map(|c| c[1].to_string())
                        })
                        .unwrap_or_else(|| "unknown".to_string());

                    let mut hasher = Sha256::new();
                    hasher.update(&body);
                    let hash = hex::encode(hasher.finalize());

                    attachments.push(Attachment {
                        filename,
                        content_type: part.ctype.mimetype.clone(),
                        size: body.len(),
                        sha256: hash,
                    });
                }
            }
        }
    }

    process_part(mail, &mut attachments);
    attachments
}

fn extract_urls(text: &str, html: &str) -> Vec<String> {
    let mut urls: HashSet<String> = HashSet::new();

    for cap in URL_REGEX.find_iter(text) {
        urls.insert(cap.as_str().trim_end_matches(&['.', ',', ')', ']', '>', ';'][..]).to_string());
    }

    for cap in URL_REGEX.find_iter(html) {
        urls.insert(cap.as_str().trim_end_matches(&['.', ',', ')', ']', '>', ';'][..]).to_string());
    }

    let href_regex = Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
    for cap in href_regex.captures_iter(html) {
        let url = &cap[1];
        if url.starts_with("http") {
            urls.insert(url.to_string());
        }
    }

    urls.into_iter().collect()
}

fn extract_domains(urls: &[String], text: &str) -> Vec<String> {
    let mut domains: HashSet<String> = HashSet::new();

    for url_str in urls {
        if let Ok(parsed_url) = url::Url::parse(url_str) {
            if let Some(host) = parsed_url.host_str() {
                domains.insert(host.to_lowercase());
            }
        }
    }

    for cap in DOMAIN_REGEX.find_iter(text) {
        let domain = cap.as_str().to_lowercase();
        if !domain.ends_with(".png") && !domain.ends_with(".jpg") &&
           !domain.ends_with(".gif") && !domain.ends_with(".css") {
            domains.insert(domain);
        }
    }

    domains.into_iter().collect()
}

fn extract_ips(headers: &[EmailHeader]) -> Vec<String> {
    let mut ips: HashSet<String> = HashSet::new();

    for header in headers {
        for cap in IP_REGEX.find_iter(&header.value) {
            let ip = cap.as_str();
            if !ip.starts_with("10.") && !ip.starts_with("192.168.") &&
               !ip.starts_with("127.") && !ip.starts_with("0.") {
                ips.insert(ip.to_string());
            }
        }
    }

    ips.into_iter().collect()
}

fn extract_email_addresses(text: &str, headers: &[EmailHeader]) -> Vec<String> {
    let mut emails: HashSet<String> = HashSet::new();

    for cap in EMAIL_REGEX.find_iter(text) {
        emails.insert(cap.as_str().to_lowercase());
    }

    for header in headers {
        for cap in EMAIL_REGEX.find_iter(&header.value) {
            emails.insert(cap.as_str().to_lowercase());
        }
    }

    emails.into_iter().collect()
}

pub fn parse_eml(content: &str) -> Result<ParsedEmail, String> {
    let mail = parse_mail(content.as_bytes())
        .map_err(|e| format!("Failed to parse email: {}", e))?;

    let headers: Vec<EmailHeader> = mail.headers.iter()
        .map(|h| EmailHeader {
            name: h.get_key().to_string(),
            value: h.get_value(),
        })
        .collect();

    let (body_text, body_html) = extract_body_parts(&mail);
    let attachments = extract_attachments(&mail);
    let authentication = parse_authentication_results(&mail);

    let urls = extract_urls(&body_text, &body_html);
    let domains = extract_domains(&urls, &body_text);
    let ip_addresses = extract_ips(&headers);
    let email_addresses = extract_email_addresses(&body_text, &headers);

    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let id = hex::encode(&hasher.finalize()[..8]);

    Ok(ParsedEmail {
        id,
        subject: extract_header(&mail, "Subject").unwrap_or_default(),
        from: extract_header(&mail, "From").unwrap_or_default(),
        to: extract_header(&mail, "To").unwrap_or_default(),
        reply_to: extract_header(&mail, "Reply-To"),
        return_path: extract_header(&mail, "Return-Path"),
        date: extract_header(&mail, "Date"),
        headers,
        body_text,
        body_html,
        urls,
        domains,
        ip_addresses,
        email_addresses,
        attachments,
        authentication,
        raw_content: content.to_string(),
    })
}
