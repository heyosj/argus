const EMAIL_PATTERN = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const PHONE_PATTERN = /(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/g;
const CREDIT_CARD_PATTERN = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g;
const SSN_PATTERN = /\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b/g;
const NAME_PATTERN = /(?:dear|hello|hi|hey)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/gi;

export const defaultRedactionOptions = {
  redact_emails: true,
  redact_phones: true,
  redact_credit_cards: true,
  redact_ssn: true,
  redact_names: true,
  custom_patterns: [],
};

export function redactText(text, options = defaultRedactionOptions) {
  let result = text;
  const redactions = [];

  if (options.redact_emails) {
    result = result.replace(EMAIL_PATTERN, (match) => {
      const parts = match.split('@');
      const redacted = parts.length === 2 ? `[REDACTED]@${parts[1]}` : '[REDACTED-EMAIL]';
      redactions.push({
        original: match,
        redacted,
        redaction_type: 'email',
      });
      return redacted;
    });
  }

  if (options.redact_phones) {
    result = result.replace(PHONE_PATTERN, (match) => {
      const redacted = '[REDACTED-PHONE]';
      redactions.push({
        original: match,
        redacted,
        redaction_type: 'phone',
      });
      return redacted;
    });
  }

  if (options.redact_credit_cards) {
    result = result.replace(CREDIT_CARD_PATTERN, (match) => {
      const redacted = '[REDACTED-CC]';
      redactions.push({
        original: match,
        redacted,
        redaction_type: 'credit_card',
      });
      return redacted;
    });
  }

  if (options.redact_ssn) {
    result = result.replace(SSN_PATTERN, (match) => {
      const redacted = '[REDACTED-SSN]';
      redactions.push({
        original: match,
        redacted,
        redaction_type: 'ssn',
      });
      return redacted;
    });
  }

  if (options.redact_names) {
    result = result.replace(NAME_PATTERN, (match, name) => {
      const redacted = match.replace(name, '[REDACTED-NAME]');
      redactions.push({
        original: name,
        redacted: '[REDACTED-NAME]',
        redaction_type: 'name',
      });
      return redacted;
    });
  }

  if (options.custom_patterns) {
    options.custom_patterns.forEach(patternStr => {
      try {
        const pattern = new RegExp(patternStr, 'g');
        result = result.replace(pattern, (match) => {
          const redacted = '[REDACTED-CUSTOM]';
          redactions.push({
            original: match,
            redacted,
            redaction_type: 'custom',
          });
          return redacted;
        });
      } catch (e) {}
    });
  }

  return {
    redacted_text: result,
    redaction_count: redactions.length,
    redactions,
  };
}
