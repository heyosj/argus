use regex::Regex;
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

static EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()
});

static PHONE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}").unwrap()
});

static CREDIT_CARD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap()
});

static SSN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b").unwrap()
});

static NAME_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:dear|hello|hi|hey)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)").unwrap()
});

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RedactionResult {
    pub redacted_text: String,
    pub redaction_count: usize,
    pub redactions: Vec<Redaction>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Redaction {
    pub original: String,
    pub redacted: String,
    pub redaction_type: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RedactionOptions {
    pub redact_emails: bool,
    pub redact_phones: bool,
    pub redact_credit_cards: bool,
    pub redact_ssn: bool,
    pub redact_names: bool,
    pub custom_patterns: Vec<String>,
}

impl Default for RedactionResult {
    fn default() -> Self {
        Self {
            redacted_text: String::new(),
            redaction_count: 0,
            redactions: Vec::new(),
        }
    }
}

pub fn redact_text(text: &str, options: &RedactionOptions) -> RedactionResult {
    let mut result = text.to_string();
    let mut redactions: Vec<Redaction> = Vec::new();
    let mut offset: i64 = 0;

    if options.redact_emails {
        for cap in EMAIL_PATTERN.find_iter(text) {
            let original = cap.as_str();
            let parts: Vec<&str> = original.split('@').collect();
            let redacted = if parts.len() == 2 {
                format!("[REDACTED]@{}", parts[1])
            } else {
                "[REDACTED-EMAIL]".to_string()
            };

            let start = (cap.start() as i64 + offset) as usize;
            let end = (cap.end() as i64 + offset) as usize;

            result = format!("{}{}{}", &result[..start], &redacted, &result[end..]);
            offset += redacted.len() as i64 - original.len() as i64;

            redactions.push(Redaction {
                original: original.to_string(),
                redacted: redacted.clone(),
                redaction_type: "email".to_string(),
                start: cap.start(),
                end: cap.end(),
            });
        }
    }

    if options.redact_phones {
        let current_text = result.clone();
        offset = 0;
        for cap in PHONE_PATTERN.find_iter(&current_text) {
            let original = cap.as_str();
            let redacted = "[REDACTED-PHONE]".to_string();

            let start = (cap.start() as i64 + offset) as usize;
            let end = (cap.end() as i64 + offset) as usize;

            result = format!("{}{}{}", &result[..start], &redacted, &result[end..]);
            offset += redacted.len() as i64 - original.len() as i64;

            redactions.push(Redaction {
                original: original.to_string(),
                redacted: redacted.clone(),
                redaction_type: "phone".to_string(),
                start: cap.start(),
                end: cap.end(),
            });
        }
    }

    if options.redact_credit_cards {
        let current_text = result.clone();
        offset = 0;
        for cap in CREDIT_CARD_PATTERN.find_iter(&current_text) {
            let original = cap.as_str();
            let redacted = "[REDACTED-CC]".to_string();

            let start = (cap.start() as i64 + offset) as usize;
            let end = (cap.end() as i64 + offset) as usize;

            result = format!("{}{}{}", &result[..start], &redacted, &result[end..]);
            offset += redacted.len() as i64 - original.len() as i64;

            redactions.push(Redaction {
                original: original.to_string(),
                redacted: redacted.clone(),
                redaction_type: "credit_card".to_string(),
                start: cap.start(),
                end: cap.end(),
            });
        }
    }

    if options.redact_ssn {
        let current_text = result.clone();
        offset = 0;
        for cap in SSN_PATTERN.find_iter(&current_text) {
            let original = cap.as_str();
            let redacted = "[REDACTED-SSN]".to_string();

            let start = (cap.start() as i64 + offset) as usize;
            let end = (cap.end() as i64 + offset) as usize;

            result = format!("{}{}{}", &result[..start], &redacted, &result[end..]);
            offset += redacted.len() as i64 - original.len() as i64;

            redactions.push(Redaction {
                original: original.to_string(),
                redacted: redacted.clone(),
                redaction_type: "ssn".to_string(),
                start: cap.start(),
                end: cap.end(),
            });
        }
    }

    if options.redact_names {
        let current_text = result.clone();
        offset = 0;
        for cap in NAME_PATTERN.captures_iter(&current_text) {
            if let Some(name_match) = cap.get(1) {
                let original = name_match.as_str();
                let redacted = "[REDACTED-NAME]".to_string();

                let start = (name_match.start() as i64 + offset) as usize;
                let end = (name_match.end() as i64 + offset) as usize;

                result = format!("{}{}{}", &result[..start], &redacted, &result[end..]);
                offset += redacted.len() as i64 - original.len() as i64;

                redactions.push(Redaction {
                    original: original.to_string(),
                    redacted: redacted.clone(),
                    redaction_type: "name".to_string(),
                    start: name_match.start(),
                    end: name_match.end(),
                });
            }
        }
    }

    for pattern_str in &options.custom_patterns {
        if let Ok(pattern) = Regex::new(pattern_str) {
            let current_text = result.clone();
            offset = 0;
            for cap in pattern.find_iter(&current_text) {
                let original = cap.as_str();
                let redacted = "[REDACTED-CUSTOM]".to_string();

                let start = (cap.start() as i64 + offset) as usize;
                let end = (cap.end() as i64 + offset) as usize;

                result = format!("{}{}{}", &result[..start], &redacted, &result[end..]);
                offset += redacted.len() as i64 - original.len() as i64;

                redactions.push(Redaction {
                    original: original.to_string(),
                    redacted: redacted.clone(),
                    redaction_type: "custom".to_string(),
                    start: cap.start(),
                    end: cap.end(),
                });
            }
        }
    }

    RedactionResult {
        redacted_text: result,
        redaction_count: redactions.len(),
        redactions,
    }
}

pub fn get_default_options() -> RedactionOptions {
    RedactionOptions {
        redact_emails: true,
        redact_phones: true,
        redact_credit_cards: true,
        redact_ssn: true,
        redact_names: true,
        custom_patterns: Vec::new(),
    }
}
