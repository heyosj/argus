use serde::{Deserialize, Serialize};
use regex::Regex;
use once_cell::sync::Lazy;
use crate::email_parser::ParsedEmail;

static URGENCY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\b(urgent|immediately|asap|right away|act now|limited time)\b").unwrap(),
        Regex::new(r"(?i)\b(expire|suspend|terminate|deactivate|close your account)\b").unwrap(),
        Regex::new(r"(?i)\b(within 24 hours|within 48 hours|today only)\b").unwrap(),
        Regex::new(r"(?i)\b(final notice|last warning|immediate action required)\b").unwrap(),
    ]
});

static CREDENTIAL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\b(verify your|confirm your|update your)\s+(account|password|credentials|identity)\b").unwrap(),
        Regex::new(r"(?i)\b(login|sign in|log in)\s+(here|now|to)\b").unwrap(),
        Regex::new(r"(?i)\b(enter your|provide your)\s+(password|credentials|ssn|social security)\b").unwrap(),
        Regex::new(r"(?i)\b(click here to|click the link|click below)\b").unwrap(),
    ]
});

static IMPERSONATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\b(paypal|microsoft|apple|amazon|netflix|bank of|wells fargo|chase)\b").unwrap(),
        Regex::new(r"(?i)\b(security team|support team|customer service|help desk)\b").unwrap(),
        Regex::new(r"(?i)\b(official|authorized|verified)\b").unwrap(),
    ]
});

static URL_SHORTENERS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "tiny.cc"
    ]
});

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatIndicator {
    pub category: String,
    pub description: String,
    pub severity: String,
    pub details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatAssessment {
    pub level: ThreatLevel,
    pub score: u32,
    pub indicators: Vec<ThreatIndicator>,
    pub summary: String,
}

pub fn analyze_threats(email: &ParsedEmail) -> ThreatAssessment {
    let mut indicators: Vec<ThreatIndicator> = Vec::new();
    let mut score: u32 = 0;

    // Check authentication failures
    if email.authentication.spf_status == "fail" {
        score += 25;
        indicators.push(ThreatIndicator {
            category: "Authentication".to_string(),
            description: "SPF check failed".to_string(),
            severity: "high".to_string(),
            details: Some("The sender's domain did not authorize this server to send emails on its behalf.".to_string()),
        });
    } else if email.authentication.spf_status == "softfail" {
        score += 10;
        indicators.push(ThreatIndicator {
            category: "Authentication".to_string(),
            description: "SPF soft fail".to_string(),
            severity: "medium".to_string(),
            details: Some("The sender's SPF policy indicates this server may not be authorized.".to_string()),
        });
    }

    if email.authentication.dkim_status == "fail" {
        score += 25;
        indicators.push(ThreatIndicator {
            category: "Authentication".to_string(),
            description: "DKIM verification failed".to_string(),
            severity: "high".to_string(),
            details: Some("The email's DKIM signature could not be verified.".to_string()),
        });
    }

    if email.authentication.dmarc_status == "fail" {
        score += 25;
        indicators.push(ThreatIndicator {
            category: "Authentication".to_string(),
            description: "DMARC check failed".to_string(),
            severity: "high".to_string(),
            details: Some("The email failed DMARC policy validation.".to_string()),
        });
    }

    // Check for Return-Path mismatch
    if let Some(return_path) = &email.return_path {
        if !return_path.is_empty() && !email.from.to_lowercase().contains(&return_path.to_lowercase()) {
            score += 15;
            indicators.push(ThreatIndicator {
                category: "Header Anomaly".to_string(),
                description: "Return-Path mismatch".to_string(),
                severity: "medium".to_string(),
                details: Some(format!("From: {} differs from Return-Path: {}", email.from, return_path)),
            });
        }
    }

    // Check for Reply-To mismatch
    if let Some(reply_to) = &email.reply_to {
        if !reply_to.is_empty() && !email.from.to_lowercase().contains(&reply_to.to_lowercase()) {
            score += 15;
            indicators.push(ThreatIndicator {
                category: "Header Anomaly".to_string(),
                description: "Reply-To mismatch".to_string(),
                severity: "medium".to_string(),
                details: Some(format!("Replies would go to {} instead of {}", reply_to, email.from)),
            });
        }
    }

    // Check for urgency language
    let combined_text = format!("{} {} {}", email.subject, email.body_text, email.body_html);
    for pattern in URGENCY_PATTERNS.iter() {
        if pattern.is_match(&combined_text) {
            score += 10;
            indicators.push(ThreatIndicator {
                category: "Social Engineering".to_string(),
                description: "Urgency language detected".to_string(),
                severity: "medium".to_string(),
                details: Some("The email uses urgent or pressure tactics common in phishing.".to_string()),
            });
            break;
        }
    }

    // Check for credential harvesting language
    for pattern in CREDENTIAL_PATTERNS.iter() {
        if pattern.is_match(&combined_text) {
            score += 20;
            indicators.push(ThreatIndicator {
                category: "Credential Harvesting".to_string(),
                description: "Credential request detected".to_string(),
                severity: "high".to_string(),
                details: Some("The email contains language requesting login or personal information.".to_string()),
            });
            break;
        }
    }

    // Check for impersonation attempts
    for pattern in IMPERSONATION_PATTERNS.iter() {
        if pattern.is_match(&combined_text) {
            // Check if the from domain matches the claimed brand
            let matched_brand = pattern.find(&combined_text).map(|m| m.as_str().to_lowercase());
            if let Some(brand) = matched_brand {
                let from_lower = email.from.to_lowercase();
                if !from_lower.contains(&brand) {
                    score += 15;
                    indicators.push(ThreatIndicator {
                        category: "Impersonation".to_string(),
                        description: format!("Possible {} impersonation", brand),
                        severity: "high".to_string(),
                        details: Some(format!("Email mentions {} but sender domain doesn't match.", brand)),
                    });
                    break;
                }
            }
        }
    }

    // Check for URL shorteners
    for url in &email.urls {
        for shortener in URL_SHORTENERS.iter() {
            if url.to_lowercase().contains(shortener) {
                score += 10;
                indicators.push(ThreatIndicator {
                    category: "Suspicious URL".to_string(),
                    description: "URL shortener detected".to_string(),
                    severity: "medium".to_string(),
                    details: Some(format!("URL shortener used: {} (may hide malicious destination)", shortener)),
                });
                break;
            }
        }
    }

    // Check for mismatched URL domains
    let from_domain = email.from.split('@').last().unwrap_or("").to_lowercase();
    for url in &email.urls {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                let host_lower = host.to_lowercase();
                if !from_domain.is_empty() && !host_lower.contains(&from_domain) && !from_domain.contains(&host_lower) {
                    score += 5;
                    indicators.push(ThreatIndicator {
                        category: "Suspicious URL".to_string(),
                        description: "External domain in links".to_string(),
                        severity: "low".to_string(),
                        details: Some(format!("Link points to {} which differs from sender domain", host)),
                    });
                    break;
                }
            }
        }
    }

    // Check for suspicious attachments
    for attachment in &email.attachments {
        let ext = attachment.filename.split('.').last().unwrap_or("").to_lowercase();
        if matches!(ext.as_str(), "exe" | "scr" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "jar" | "msi") {
            score += 30;
            indicators.push(ThreatIndicator {
                category: "Malicious Attachment".to_string(),
                description: format!("Dangerous file type: .{}", ext),
                severity: "high".to_string(),
                details: Some(format!("Attachment '{}' is an executable file type", attachment.filename)),
            });
        } else if matches!(ext.as_str(), "zip" | "rar" | "7z" | "iso" | "img") {
            score += 10;
            indicators.push(ThreatIndicator {
                category: "Suspicious Attachment".to_string(),
                description: format!("Archive file type: .{}", ext),
                severity: "medium".to_string(),
                details: Some(format!("Attachment '{}' is an archive that may contain malware", attachment.filename)),
            });
        }
    }

    // Determine threat level
    let level = if score >= 50 {
        ThreatLevel::High
    } else if score >= 25 {
        ThreatLevel::Medium
    } else {
        ThreatLevel::Low
    };

    let summary = match level {
        ThreatLevel::High => "This email shows multiple high-risk indicators consistent with phishing or malicious intent.".to_string(),
        ThreatLevel::Medium => "This email shows some suspicious characteristics that warrant caution.".to_string(),
        ThreatLevel::Low => "This email shows minimal suspicious indicators but should still be verified.".to_string(),
    };

    ThreatAssessment {
        level,
        score,
        indicators,
        summary,
    }
}
