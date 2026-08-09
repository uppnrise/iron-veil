use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiType {
    Email,
    CreditCard,
    Ssn,
    Phone,
    IpAddress,
    DateOfBirth,
    Passport,
}

impl PiiType {
    /// Parse the config-facing heuristic type name (see config::KNOWN_HEURISTIC_TYPES).
    pub fn from_config_name(name: &str) -> Option<Self> {
        match name {
            "email" => Some(Self::Email),
            "credit_card" => Some(Self::CreditCard),
            "ssn" => Some(Self::Ssn),
            "phone" => Some(Self::Phone),
            "ip" => Some(Self::IpAddress),
            "dob" => Some(Self::DateOfBirth),
            "passport" => Some(Self::Passport),
            _ => None,
        }
    }

    pub fn all() -> HashSet<Self> {
        [
            Self::Email,
            Self::CreditCard,
            Self::Ssn,
            Self::Phone,
            Self::IpAddress,
            Self::DateOfBirth,
            Self::Passport,
        ]
        .into_iter()
        .collect()
    }
}

pub struct PiiScanner {
    email_regex: Regex,
    cc_regex: Regex,
    ssn_regex: Regex,
    phone_regex: Regex,
    ip_regex: Regex,
    dob_regex: Regex,
    passport_regex: Regex,
    email_span_regex: Regex,
    phone_span_regex: Regex,
}

static SHARED_SCANNER: LazyLock<PiiScanner> = LazyLock::new(PiiScanner::compile);

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Luhn checksum over a digits-only candidate. Used to keep the credit-card
/// heuristic from rewriting arbitrary 13-19 digit identifiers.
fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut alternate = false;
    for c in digits.chars().rev() {
        let Some(d) = c.to_digit(10) else {
            return false;
        };
        let d = if alternate {
            let doubled = d * 2;
            if doubled > 9 { doubled - 9 } else { doubled }
        } else {
            d
        };
        sum += d;
        alternate = !alternate;
    }
    sum.is_multiple_of(10)
}

impl PiiScanner {
    fn compile() -> Self {
        // All patterns are compile-time constants; the unit tests in this
        // module exercise every one, so a bad edit fails in CI, not at runtime.
        Self {
            // Simple email regex
            email_regex: Regex::new(r"(?i)^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$").unwrap(),
            // Credit card: 13-19 digits with optional single space/dash
            // separators. Candidates are additionally Luhn-validated.
            cc_regex: Regex::new(r"^\d(?:[-\s]?\d){12,18}$").unwrap(),
            // US SSN: XXX-XX-XXXX format
            ssn_regex: Regex::new(r"^\d{3}-\d{2}-\d{4}$").unwrap(),
            // Phone: requires visible phone formatting (separators, parens or
            // a leading +) so bare 10-digit identifiers are not rewritten.
            // Matches: +1-555-123-4567, (555) 123-4567, 555-123-4567, 555.123.4567
            phone_regex: Regex::new(
                r"^(?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]?\d{4}$",
            )
            .unwrap(),
            // IPv4 address
            ip_regex: Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap(),
            // Date of birth: YYYY-MM-DD, MM/DD/YYYY, DD/MM/YYYY, DD-MM-YYYY
            dob_regex: Regex::new(r"^(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})$").unwrap(),
            // Passport: Basic pattern for common formats (alphanumeric, 6-9 chars)
            passport_regex: Regex::new(r"^[A-Z]{1,2}\d{6,8}$").unwrap(),
            // Unanchored variants for masking PII embedded in free text.
            email_span_regex: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
                .unwrap(),
            // Boundary groups stand in for lookarounds (unsupported by the
            // regex crate) so we never match inside a longer digit run.
            phone_span_regex: Regex::new(
                r"(^|[^0-9A-Za-z._%+-])((?:\+\d{1,3}[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]?\d{4})($|[^0-9])",
            )
            .unwrap(),
        }
    }

    pub fn new() -> Self {
        Self::compile()
    }

    /// Shared process-wide scanner; avoids recompiling the regexes per connection.
    pub fn shared() -> &'static Self {
        &SHARED_SCANNER
    }

    /// Scan for any known PII type (used by the offline /scan reporting path).
    pub fn scan(&self, text: &str) -> Option<PiiType> {
        static ALL_PII_TYPES: LazyLock<HashSet<PiiType>> = LazyLock::new(PiiType::all);
        self.scan_allowed(text, &ALL_PII_TYPES)
    }

    /// Scan for the subset of PII types enabled for runtime heuristics.
    pub fn scan_allowed(&self, text: &str, allowed: &HashSet<PiiType>) -> Option<PiiType> {
        // Check patterns in order of specificity
        if allowed.contains(&PiiType::Email) && self.email_regex.is_match(text) {
            return Some(PiiType::Email);
        }
        if allowed.contains(&PiiType::CreditCard) && self.cc_regex.is_match(text) {
            let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
            if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
                return Some(PiiType::CreditCard);
            }
        }
        if allowed.contains(&PiiType::Ssn) && self.ssn_regex.is_match(text) {
            return Some(PiiType::Ssn);
        }
        if allowed.contains(&PiiType::IpAddress) && self.ip_regex.is_match(text) {
            return Some(PiiType::IpAddress);
        }
        // Check date before phone to avoid false positives
        if allowed.contains(&PiiType::DateOfBirth) && self.dob_regex.is_match(text) {
            return Some(PiiType::DateOfBirth);
        }
        if allowed.contains(&PiiType::Phone) && self.phone_regex.is_match(text) {
            return Some(PiiType::Phone);
        }
        if allowed.contains(&PiiType::Passport) && self.passport_regex.is_match(text) {
            return Some(PiiType::Passport);
        }
        None
    }

    /// Mask email/phone occurrences embedded in free text (the whole-value
    /// detectors above never fire on prose). Returns None when nothing matched.
    /// Only email and phone are searched for unanchored — the other detectors
    /// are far too ambiguous mid-text.
    pub fn mask_text_spans(
        &self,
        text: &str,
        allowed: &HashSet<PiiType>,
        mut replace: impl FnMut(PiiType, &str) -> String,
    ) -> Option<String> {
        let mut current = text.to_string();
        let mut changed = false;

        if allowed.contains(&PiiType::Email) && self.email_span_regex.is_match(&current) {
            let masked = self
                .email_span_regex
                .replace_all(&current, |caps: &regex::Captures| {
                    replace(PiiType::Email, &caps[0])
                });
            if masked != current {
                current = masked.into_owned();
                changed = true;
            }
        }

        if allowed.contains(&PiiType::Phone) {
            // Manual assembly: replace only capture group 2, keeping the
            // boundary characters from groups 1 and 3 intact.
            let mut out = String::with_capacity(current.len());
            let mut last_end = 0;
            let mut any = false;
            for caps in self.phone_span_regex.captures_iter(&current) {
                let m = caps.get(2).expect("phone span group");
                out.push_str(&current[last_end..m.start()]);
                out.push_str(&replace(PiiType::Phone, m.as_str()));
                last_end = m.end();
                any = true;
            }
            if any {
                out.push_str(&current[last_end..]);
                current = out;
                changed = true;
            }
        }

        if changed { Some(current) } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let scanner = PiiScanner::new();

        // Valid emails
        assert_eq!(scanner.scan("test@example.com"), Some(PiiType::Email));
        assert_eq!(scanner.scan("john.doe@company.org"), Some(PiiType::Email));
        assert_eq!(scanner.scan("user+tag@domain.co.uk"), Some(PiiType::Email));
        assert_eq!(scanner.scan("USER@EXAMPLE.COM"), Some(PiiType::Email));

        // Invalid emails
        assert_eq!(scanner.scan("not-an-email"), None);
        assert_eq!(scanner.scan("missing@domain"), None);
        assert_eq!(scanner.scan("@nodomain.com"), None);
        assert_eq!(scanner.scan("spaces in@email.com"), None);
    }

    #[test]
    fn test_credit_card_detection() {
        let scanner = PiiScanner::new();

        // Valid (Luhn-passing) cards
        assert_eq!(
            scanner.scan("4532-0151-1283-0366"),
            Some(PiiType::CreditCard)
        );
        assert_eq!(
            scanner.scan("4532 0151 1283 0366"),
            Some(PiiType::CreditCard)
        );
        assert_eq!(scanner.scan("4532015112830366"), Some(PiiType::CreditCard));
        // 15-digit Amex and 14-digit Diners
        assert_eq!(scanner.scan("378282246310005"), Some(PiiType::CreditCard));
        assert_eq!(scanner.scan("30569309025904"), Some(PiiType::CreditCard));

        // Luhn-failing 16-digit identifier must NOT be treated as a card
        assert_eq!(scanner.scan("1234567890123456"), None);
        assert_eq!(scanner.scan("1234-5678-9012-3456"), None);

        // Invalid shapes
        assert_eq!(scanner.scan("1234-5678-9012"), None);
        assert_eq!(scanner.scan("not a credit card"), None);
        assert_eq!(scanner.scan("12345678901234567890"), None); // Too long
    }

    #[test]
    fn test_ssn_detection() {
        let scanner = PiiScanner::new();

        // Valid SSNs
        assert_eq!(scanner.scan("123-45-6789"), Some(PiiType::Ssn));
        assert_eq!(scanner.scan("000-00-0000"), Some(PiiType::Ssn));

        // Invalid SSNs
        assert_eq!(scanner.scan("123456789"), None);
        assert_eq!(scanner.scan("123-456-789"), None);
        assert_eq!(scanner.scan("12-345-6789"), None);
    }

    #[test]
    fn test_phone_detection() {
        let scanner = PiiScanner::new();

        // Valid US phone numbers (10 digits, with visible formatting)
        assert_eq!(scanner.scan("+1-555-123-4567"), Some(PiiType::Phone));
        assert_eq!(scanner.scan("555-123-4567"), Some(PiiType::Phone));
        assert_eq!(scanner.scan("(555) 123-4567"), Some(PiiType::Phone));
        assert_eq!(scanner.scan("555.123.4567"), Some(PiiType::Phone));

        // Bare digit runs are identifiers, not phones
        assert_eq!(scanner.scan("5551234567"), None);

        // Invalid phone numbers
        assert_eq!(scanner.scan("phone"), None);
        assert_eq!(scanner.scan("12"), None);
        assert_eq!(scanner.scan("12345"), None);
    }

    #[test]
    fn test_ip_address_detection() {
        let scanner = PiiScanner::new();

        // Valid IP addresses
        assert_eq!(scanner.scan("192.168.1.1"), Some(PiiType::IpAddress));
        assert_eq!(scanner.scan("10.0.0.1"), Some(PiiType::IpAddress));
        assert_eq!(scanner.scan("255.255.255.255"), Some(PiiType::IpAddress));
        assert_eq!(scanner.scan("0.0.0.0"), Some(PiiType::IpAddress));

        // Invalid IP addresses
        assert_eq!(scanner.scan("256.1.1.1"), None);
        assert_eq!(scanner.scan("192.168.1"), None);
        assert_eq!(scanner.scan("192.168.1.1.1"), None);
    }

    #[test]
    fn test_dob_detection() {
        let scanner = PiiScanner::new();

        // Valid date formats
        assert_eq!(scanner.scan("1990-01-15"), Some(PiiType::DateOfBirth));
        assert_eq!(scanner.scan("01/15/1990"), Some(PiiType::DateOfBirth));
        assert_eq!(scanner.scan("15-01-1990"), Some(PiiType::DateOfBirth));
        assert_eq!(scanner.scan("2000/12/31"), Some(PiiType::DateOfBirth));

        // Invalid dates
        assert_eq!(scanner.scan("1990"), None);
        assert_eq!(scanner.scan("Jan 15, 1990"), None);
    }

    #[test]
    fn test_passport_detection() {
        let scanner = PiiScanner::new();

        // Valid passport formats
        assert_eq!(scanner.scan("AB1234567"), Some(PiiType::Passport));
        assert_eq!(scanner.scan("C12345678"), Some(PiiType::Passport));

        // Invalid passport formats
        assert_eq!(scanner.scan("abc123456"), None); // lowercase
        assert_eq!(scanner.scan("12345678"), None); // no letter prefix
    }

    #[test]
    fn test_non_pii_data() {
        let scanner = PiiScanner::new();

        assert_eq!(scanner.scan("John Doe"), None);
        assert_eq!(scanner.scan("123 Main Street"), None);
        assert_eq!(scanner.scan("Hello, World!"), None);
        assert_eq!(scanner.scan(""), None);
        assert_eq!(scanner.scan("12345"), None);
    }

    #[test]
    fn test_scan_allowed_filters_types() {
        let scanner = PiiScanner::new();
        let mut allowed = HashSet::new();
        allowed.insert(PiiType::Email);

        assert_eq!(
            scanner.scan_allowed("test@example.com", &allowed),
            Some(PiiType::Email)
        );
        // Dates/IPs are not rewritten unless their detector is enabled
        assert_eq!(scanner.scan_allowed("2026-01-15", &allowed), None);
        assert_eq!(scanner.scan_allowed("192.168.1.1", &allowed), None);
        assert_eq!(scanner.scan_allowed("555-123-4567", &allowed), None);
    }

    #[test]
    fn test_mask_text_spans_email() {
        let scanner = PiiScanner::new();
        let allowed = PiiType::all();

        let masked = scanner
            .mask_text_spans(
                "contact john.doe@company.org for details",
                &allowed,
                |_, _| "MASKED".to_string(),
            )
            .unwrap();
        assert_eq!(masked, "contact MASKED for details");

        // No PII in text -> None
        assert!(
            scanner
                .mask_text_spans("nothing to see here", &allowed, |_, _| "X".to_string())
                .is_none()
        );
    }

    #[test]
    fn test_mask_text_spans_phone_respects_boundaries() {
        let scanner = PiiScanner::new();
        let allowed = PiiType::all();

        let masked = scanner
            .mask_text_spans("call 555-123-4567 today", &allowed, |_, _| {
                "PHONE".to_string()
            })
            .unwrap();
        assert_eq!(masked, "call PHONE today");

        // A phone-shaped substring inside a longer digit run must not match
        assert!(
            scanner
                .mask_text_spans("id 99555-123-45678 end", &allowed, |_, _| {
                    "PHONE".to_string()
                })
                .is_none()
        );
    }

    #[test]
    fn test_luhn() {
        assert!(luhn_valid("4532015112830366"));
        assert!(luhn_valid("378282246310005"));
        assert!(!luhn_valid("4532015112830367"));
    }

    #[test]
    fn test_default_trait() {
        let scanner = PiiScanner::default();
        assert_eq!(scanner.scan("test@example.com"), Some(PiiType::Email));
    }

    #[test]
    fn test_shared_scanner() {
        assert_eq!(
            PiiScanner::shared().scan("test@example.com"),
            Some(PiiType::Email)
        );
    }
}
