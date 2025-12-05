use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub enum PiiType {
    Email,
    CreditCard,
    Ssn,
    Phone,
    IpAddress,
    DateOfBirth,
    Passport,
}

pub struct PiiScanner {
    email_regex: Regex,
    cc_regex: Regex,
    ssn_regex: Regex,
    phone_regex: Regex,
    ip_regex: Regex,
    dob_regex: Regex,
    passport_regex: Regex,
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiScanner {
    pub fn new() -> Self {
        Self {
            // Simple email regex
            email_regex: Regex::new(r"(?i)^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$").unwrap(),
            // Credit Card regex (13-19 digits, optional dashes/spaces)
            cc_regex: Regex::new(r"^(?:\d{4}[-\s]?){3}\d{4}$").unwrap(),
            // US SSN: XXX-XX-XXXX format
            ssn_regex: Regex::new(r"^\d{3}-\d{2}-\d{4}$").unwrap(),
            // Phone: Must have at least 10 digits total and include formatting
            // Matches: +1-555-123-4567, (555) 123-4567, 555-123-4567, +44 20 7946 0958
            phone_regex: Regex::new(r"^(?:\+\d{1,3}[-.\s])?\(?(\d{3})\)?[-.\s]?\d{3}[-.\s]?\d{4}$").unwrap(),
            // IPv4 address
            ip_regex: Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap(),
            // Date of birth: YYYY-MM-DD, MM/DD/YYYY, DD/MM/YYYY, DD-MM-YYYY
            dob_regex: Regex::new(r"^(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})$").unwrap(),
            // Passport: Basic pattern for common formats (alphanumeric, 6-9 chars)
            passport_regex: Regex::new(r"^[A-Z]{1,2}\d{6,8}$").unwrap(),
        }
    }

    pub fn scan(&self, text: &str) -> Option<PiiType> {
        // Check patterns in order of specificity
        if self.email_regex.is_match(text) {
            return Some(PiiType::Email);
        }
        if self.cc_regex.is_match(text) {
            return Some(PiiType::CreditCard);
        }
        if self.ssn_regex.is_match(text) {
            return Some(PiiType::Ssn);
        }
        if self.ip_regex.is_match(text) {
            return Some(PiiType::IpAddress);
        }
        // Check date before phone to avoid false positives
        if self.dob_regex.is_match(text) {
            return Some(PiiType::DateOfBirth);
        }
        if self.phone_regex.is_match(text) {
            return Some(PiiType::Phone);
        }
        if self.passport_regex.is_match(text) {
            return Some(PiiType::Passport);
        }
        None
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

        // Valid credit cards
        assert_eq!(
            scanner.scan("1234-5678-9012-3456"),
            Some(PiiType::CreditCard)
        );
        assert_eq!(
            scanner.scan("1234 5678 9012 3456"),
            Some(PiiType::CreditCard)
        );
        assert_eq!(scanner.scan("1234567890123456"), Some(PiiType::CreditCard));

        // Invalid credit cards
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

        // Valid US phone numbers (10 digits)
        assert_eq!(scanner.scan("+1-555-123-4567"), Some(PiiType::Phone));
        assert_eq!(scanner.scan("555-123-4567"), Some(PiiType::Phone));
        assert_eq!(scanner.scan("(555) 123-4567"), Some(PiiType::Phone));
        assert_eq!(scanner.scan("555.123.4567"), Some(PiiType::Phone));

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
    fn test_default_trait() {
        let scanner = PiiScanner::default();
        assert_eq!(scanner.scan("test@example.com"), Some(PiiType::Email));
    }
}
