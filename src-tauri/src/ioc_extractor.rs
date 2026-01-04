use serde::{Deserialize, Serialize};
use crate::email_parser::ParsedEmail;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IOCReport {
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub email_addresses: Vec<String>,
    pub file_hashes: Vec<FileHash>,
    pub headers_of_interest: Vec<HeaderOfInterest>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileHash {
    pub filename: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeaderOfInterest {
    pub name: String,
    pub value: String,
    pub reason: String,
}

pub fn defang_url(url: &str) -> String {
    url.replace("http://", "hxxp://")
       .replace("https://", "hxxps://")
       .replace(".", "[.]")
}

pub fn defang_domain(domain: &str) -> String {
    domain.replace(".", "[.]")
}

pub fn defang_email(email: &str) -> String {
    email.replace("@", "[@]")
         .replace(".", "[.]")
}

pub fn defang_ip(ip: &str) -> String {
    ip.replace(".", "[.]")
}

pub fn extract_iocs(email: &ParsedEmail) -> IOCReport {
    let defanged_domains: Vec<String> = email.domains.iter()
        .map(|d| defang_domain(d))
        .collect();

    let defanged_urls: Vec<String> = email.urls.iter()
        .map(|u| defang_url(u))
        .collect();

    let defanged_ips: Vec<String> = email.ip_addresses.iter()
        .map(|ip| defang_ip(ip))
        .collect();

    let defanged_emails: Vec<String> = email.email_addresses.iter()
        .map(|e| defang_email(e))
        .collect();

    let file_hashes: Vec<FileHash> = email.attachments.iter()
        .map(|a| FileHash {
            filename: a.filename.clone(),
            sha256: a.sha256.clone(),
        })
        .collect();

    let mut headers_of_interest: Vec<HeaderOfInterest> = Vec::new();

    for header in &email.headers {
        let name_lower = header.name.to_lowercase();

        if name_lower == "x-originating-ip" {
            headers_of_interest.push(HeaderOfInterest {
                name: header.name.clone(),
                value: header.value.clone(),
                reason: "Source IP of the email sender".to_string(),
            });
        }

        if name_lower == "x-mailer" {
            headers_of_interest.push(HeaderOfInterest {
                name: header.name.clone(),
                value: header.value.clone(),
                reason: "Email client used to send the message".to_string(),
            });
        }

        if name_lower == "received" && header.value.to_lowercase().contains("from") {
            if headers_of_interest.iter().filter(|h| h.name.to_lowercase() == "received").count() < 3 {
                headers_of_interest.push(HeaderOfInterest {
                    name: header.name.clone(),
                    value: header.value.clone(),
                    reason: "Email routing information".to_string(),
                });
            }
        }
    }

    if let (Some(from), Some(return_path)) = (&Some(email.from.clone()), &email.return_path) {
        if !from.is_empty() && !return_path.is_empty() && !from.contains(return_path) && !return_path.contains(from) {
            headers_of_interest.push(HeaderOfInterest {
                name: "Return-Path Mismatch".to_string(),
                value: format!("From: {} | Return-Path: {}", from, return_path),
                reason: "Return-Path does not match From address - possible spoofing".to_string(),
            });
        }
    }

    if let Some(reply_to) = &email.reply_to {
        if !reply_to.is_empty() && !email.from.contains(reply_to) {
            headers_of_interest.push(HeaderOfInterest {
                name: "Reply-To Mismatch".to_string(),
                value: format!("From: {} | Reply-To: {}", email.from, reply_to),
                reason: "Reply-To does not match From address - possible redirect".to_string(),
            });
        }
    }

    headers_of_interest.push(HeaderOfInterest {
        name: "SPF".to_string(),
        value: email.authentication.spf_status.clone(),
        reason: "SPF validation result".to_string(),
    });

    headers_of_interest.push(HeaderOfInterest {
        name: "DKIM".to_string(),
        value: email.authentication.dkim_status.clone(),
        reason: "DKIM validation result".to_string(),
    });

    headers_of_interest.push(HeaderOfInterest {
        name: "DMARC".to_string(),
        value: email.authentication.dmarc_status.clone(),
        reason: "DMARC validation result".to_string(),
    });

    IOCReport {
        domains: defanged_domains,
        urls: defanged_urls,
        ip_addresses: defanged_ips,
        email_addresses: defanged_emails,
        file_hashes,
        headers_of_interest,
    }
}

pub fn format_iocs_for_copy(iocs: &IOCReport) -> String {
    let mut output = String::new();

    if !iocs.domains.is_empty() {
        output.push_str("## Domains\n");
        for domain in &iocs.domains {
            output.push_str(&format!("- {}\n", domain));
        }
        output.push('\n');
    }

    if !iocs.urls.is_empty() {
        output.push_str("## URLs\n");
        for url in &iocs.urls {
            output.push_str(&format!("- {}\n", url));
        }
        output.push('\n');
    }

    if !iocs.ip_addresses.is_empty() {
        output.push_str("## IP Addresses\n");
        for ip in &iocs.ip_addresses {
            output.push_str(&format!("- {}\n", ip));
        }
        output.push('\n');
    }

    if !iocs.email_addresses.is_empty() {
        output.push_str("## Email Addresses\n");
        for email in &iocs.email_addresses {
            output.push_str(&format!("- {}\n", email));
        }
        output.push('\n');
    }

    if !iocs.file_hashes.is_empty() {
        output.push_str("## File Hashes\n");
        for hash in &iocs.file_hashes {
            output.push_str(&format!("- {}: SHA256: {}\n", hash.filename, hash.sha256));
        }
        output.push('\n');
    }

    if !iocs.headers_of_interest.is_empty() {
        output.push_str("## Headers of Interest\n");
        for header in &iocs.headers_of_interest {
            output.push_str(&format!("- {}: {}\n", header.name, header.value));
        }
    }

    output
}
