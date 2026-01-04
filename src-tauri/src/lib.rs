mod email_parser;
mod redactor;
mod ioc_extractor;
mod threat_analyzer;

#[cfg(test)]
mod test_parse;

use email_parser::ParsedEmail;
use redactor::{RedactionOptions, RedactionResult};
use ioc_extractor::IOCReport;
use threat_analyzer::ThreatAssessment;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalysisResult {
    pub email: ParsedEmail,
    pub redaction: RedactionResult,
    pub iocs: IOCReport,
    pub threat: ThreatAssessment,
    pub analyzed_at: String,
}

#[tauri::command]
fn parse_email(content: String) -> Result<AnalysisResult, String> {
    let email = email_parser::parse_eml(&content)?;

    let redaction_options = redactor::get_default_options();
    let redacted_body = redactor::redact_text(&email.body_text, &redaction_options);

    let iocs = ioc_extractor::extract_iocs(&email);
    let threat = threat_analyzer::analyze_threats(&email);

    let analyzed_at = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    Ok(AnalysisResult {
        email,
        redaction: redacted_body,
        iocs,
        threat,
        analyzed_at,
    })
}

#[tauri::command]
fn parse_email_file(file_path: String) -> Result<AnalysisResult, String> {
    let content = fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    parse_email(content)
}

#[tauri::command]
fn redact_text(text: String, options: RedactionOptions) -> RedactionResult {
    redactor::redact_text(&text, &options)
}

#[tauri::command]
fn get_iocs_formatted(email: ParsedEmail) -> String {
    let iocs = ioc_extractor::extract_iocs(&email);
    ioc_extractor::format_iocs_for_copy(&iocs)
}

#[tauri::command]
fn export_markdown(result: AnalysisResult) -> String {
    let threat_level = match result.threat.level {
        threat_analyzer::ThreatLevel::High => "High",
        threat_analyzer::ThreatLevel::Medium => "Medium",
        threat_analyzer::ThreatLevel::Low => "Low",
    };

    let threat_emoji = match result.threat.level {
        threat_analyzer::ThreatLevel::High => "🔴",
        threat_analyzer::ThreatLevel::Medium => "🟡",
        threat_analyzer::ThreatLevel::Low => "🟢",
    };

    let mut md = format!(
r#"# {} Analysis

**Analysis Date:** {}
**Threat Level:** {} {}

## Summary

{}

## Email Details

| Field | Value |
|-------|-------|
| From | {} |
| To | {} |
| Subject | {} |
| Date | {} |
| Reply-To | {} |
| Return-Path | {} |

## Authentication Results

| Check | Status |
|-------|--------|
| SPF | {} |
| DKIM | {} |
| DMARC | {} |

"#,
        result.email.subject,
        result.analyzed_at,
        threat_emoji,
        threat_level,
        result.threat.summary,
        result.email.from,
        result.email.to,
        result.email.subject,
        result.email.date.unwrap_or_else(|| "Unknown".to_string()),
        result.email.reply_to.unwrap_or_else(|| "Not specified".to_string()),
        result.email.return_path.unwrap_or_else(|| "Not specified".to_string()),
        result.email.authentication.spf_status.to_uppercase(),
        result.email.authentication.dkim_status.to_uppercase(),
        result.email.authentication.dmarc_status.to_uppercase(),
    );

    if !result.threat.indicators.is_empty() {
        md.push_str("## Threat Indicators\n\n");
        for indicator in &result.threat.indicators {
            let severity_emoji = match indicator.severity.as_str() {
                "high" => "🔴",
                "medium" => "🟡",
                _ => "🟢",
            };
            md.push_str(&format!("- {} **{}**: {}\n", severity_emoji, indicator.category, indicator.description));
            if let Some(details) = &indicator.details {
                md.push_str(&format!("  - {}\n", details));
            }
        }
        md.push('\n');
    }

    md.push_str("## Indicators of Compromise\n\n");

    if !result.iocs.domains.is_empty() {
        md.push_str("### Domains\n");
        for domain in &result.iocs.domains {
            md.push_str(&format!("- {}\n", domain));
        }
        md.push('\n');
    }

    if !result.iocs.urls.is_empty() {
        md.push_str("### URLs\n");
        for url in &result.iocs.urls {
            md.push_str(&format!("- {}\n", url));
        }
        md.push('\n');
    }

    if !result.iocs.ip_addresses.is_empty() {
        md.push_str("### IP Addresses\n");
        for ip in &result.iocs.ip_addresses {
            md.push_str(&format!("- {}\n", ip));
        }
        md.push('\n');
    }

    if !result.iocs.email_addresses.is_empty() {
        md.push_str("### Email Addresses\n");
        for email in &result.iocs.email_addresses {
            md.push_str(&format!("- {}\n", email));
        }
        md.push('\n');
    }

    if !result.iocs.file_hashes.is_empty() {
        md.push_str("### File Hashes\n");
        for hash in &result.iocs.file_hashes {
            md.push_str(&format!("- {}: SHA256: {}\n", hash.filename, hash.sha256));
        }
        md.push('\n');
    }

    if !result.iocs.headers_of_interest.is_empty() {
        md.push_str("### Headers of Interest\n");
        for header in &result.iocs.headers_of_interest {
            md.push_str(&format!("- {}: {}\n", header.name, header.value));
        }
        md.push('\n');
    }

    md.push_str("## Email Body (Redacted)\n\n");
    md.push_str("```\n");
    md.push_str(&result.redaction.redacted_text);
    md.push_str("\n```\n");

    md
}

#[tauri::command]
fn export_json(result: AnalysisResult) -> Result<String, String> {
    serde_json::to_string_pretty(&result)
        .map_err(|e| format!("Failed to serialize to JSON: {}", e))
}

#[tauri::command]
fn export_sanitized_eml(result: AnalysisResult) -> String {
    let mut sanitized = result.email.raw_content.clone();

    for redaction in &result.redaction.redactions {
        sanitized = sanitized.replace(&redaction.original, &redaction.redacted);
    }

    sanitized
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            parse_email,
            parse_email_file,
            redact_text,
            get_iocs_formatted,
            export_markdown,
            export_json,
            export_sanitized_eml
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
