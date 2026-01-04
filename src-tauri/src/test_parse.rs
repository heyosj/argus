// Quick test module
#[cfg(test)]
mod tests {
    use crate::email_parser::parse_eml;
    use crate::threat_analyzer::analyze_threats;
    use crate::ioc_extractor::extract_iocs;
    use crate::redactor::{redact_text, get_default_options};

    const TEST_EMAIL: &str = r#"Received: from mail-evil.attacker.com (mail-evil.attacker.com [185.234.72.19])
        by mx.victim.com with ESMTP id abc123
        for <john.doe@company.com>; Sat, 4 Jan 2025 10:30:00 -0500
Authentication-Results: mx.victim.com;
        spf=fail smtp.mailfrom=security@paypal.com;
        dkim=fail;
        dmarc=fail header.from=paypal.com
Received-SPF: fail (domain of paypal.com does not designate 185.234.72.19 as permitted sender)
From: PayPal Security Team <security@paypal.com>
Reply-To: paypal-verify-account@gmail.com
Return-Path: <bounces@attacker-domain.xyz>
To: john.doe@company.com
Subject: URGENT: Your PayPal Account Has Been Limited
Date: Sat, 4 Jan 2025 10:30:00 -0500
X-Originating-IP: [185.234.72.19]
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Dear John Doe,

URGENT: Your account has been limited! Verify immediately at:
https://paypa1-secure-verify.bit.ly/account/restore
https://www.paypal-security-check.com/verify.php

Enter your password and SSN: 123-45-6789
Call us at 1-800-555-0123 or email support@paypal-help.net
"#;

    #[test]
    fn test_email_parsing() {
        let result = parse_eml(TEST_EMAIL);
        assert!(result.is_ok());
        let email = result.unwrap();

        assert_eq!(email.subject, "URGENT: Your PayPal Account Has Been Limited");
        assert!(email.from.contains("paypal.com"));
        assert!(email.reply_to.is_some());
        assert!(email.return_path.is_some());

        println!("Subject: {}", email.subject);
        println!("From: {}", email.from);
        println!("Reply-To: {:?}", email.reply_to);
        println!("Return-Path: {:?}", email.return_path);
        println!("URLs found: {:?}", email.urls);
        println!("Domains found: {:?}", email.domains);
        println!("IPs found: {:?}", email.ip_addresses);
        println!("Auth SPF: {}", email.authentication.spf_status);
        println!("Auth DKIM: {}", email.authentication.dkim_status);
        println!("Auth DMARC: {}", email.authentication.dmarc_status);
    }

    #[test]
    fn test_threat_analysis() {
        let email = parse_eml(TEST_EMAIL).unwrap();
        let threat = analyze_threats(&email);

        println!("\n=== THREAT ANALYSIS ===");
        println!("Level: {:?}", threat.level);
        println!("Score: {}", threat.score);
        println!("Summary: {}", threat.summary);
        println!("\nIndicators:");
        for indicator in &threat.indicators {
            println!("  [{:?}] {}: {}", indicator.severity, indicator.category, indicator.description);
        }

        // Should be high threat
        assert!(threat.score >= 50, "Expected high threat score, got {}", threat.score);
    }

    #[test]
    fn test_ioc_extraction() {
        let email = parse_eml(TEST_EMAIL).unwrap();
        let iocs = extract_iocs(&email);

        println!("\n=== IOC EXTRACTION ===");
        println!("Domains: {:?}", iocs.domains);
        println!("URLs: {:?}", iocs.urls);
        println!("IPs: {:?}", iocs.ip_addresses);
        println!("Emails: {:?}", iocs.email_addresses);

        assert!(!iocs.domains.is_empty());
        assert!(!iocs.urls.is_empty());
    }

    #[test]
    fn test_redaction() {
        let text = "Contact john@example.com or call 555-123-4567. SSN: 123-45-6789";
        let options = get_default_options();
        let result = redact_text(text, &options);

        println!("\n=== REDACTION ===");
        println!("Original: {}", text);
        println!("Redacted: {}", result.redacted_text);
        println!("Count: {}", result.redaction_count);

        assert!(result.redaction_count > 0);
        assert!(result.redacted_text.contains("[REDACTED]"));
    }
}
