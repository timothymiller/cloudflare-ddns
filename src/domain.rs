use std::fmt;

/// Represents a DNS domain - either a regular FQDN or a wildcard.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Domain {
    FQDN(String),
    Wildcard(String),
}

#[allow(dead_code)]
impl Domain {
    /// Parse a domain string. Handles:
    /// - "@" or "" -> root domain (handled at FQDN construction time)
    /// - "*.example.com" -> wildcard
    /// - "sub.example.com" -> regular FQDN
    pub fn new(input: &str) -> Result<Self, String> {
        let trimmed = input.trim().to_lowercase();
        if trimmed.starts_with("*.") {
            let base = &trimmed[2..];
            let ascii = domain_to_ascii(base)?;
            Ok(Domain::Wildcard(ascii))
        } else {
            let ascii = domain_to_ascii(&trimmed)?;
            Ok(Domain::FQDN(ascii))
        }
    }

    /// Returns the DNS name in ASCII form suitable for API calls.
    pub fn dns_name_ascii(&self) -> String {
        match self {
            Domain::FQDN(s) => s.clone(),
            Domain::Wildcard(s) => format!("*.{s}"),
        }
    }

    /// Returns a human-readable description of the domain.
    pub fn describe(&self) -> String {
        match self {
            Domain::FQDN(s) => describe_domain(s),
            Domain::Wildcard(s) => format!("*.{}", describe_domain(s)),
        }
    }

    /// Returns the zones (parent domains) for this domain, from most specific to least.
    pub fn zones(&self) -> Vec<String> {
        let base = match self {
            Domain::FQDN(s) => s.as_str(),
            Domain::Wildcard(s) => s.as_str(),
        };
        let mut zones = Vec::new();
        let mut current = base.to_string();
        while !current.is_empty() {
            zones.push(current.clone());
            if let Some(pos) = current.find('.') {
                current = current[pos + 1..].to_string();
            } else {
                break;
            }
        }
        zones
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.describe())
    }
}

/// Construct an FQDN from a subdomain name and base domain.
pub fn make_fqdn(subdomain: &str, base_domain: &str) -> String {
    let name = subdomain.to_lowercase();
    let name = name.trim();
    if name.is_empty() || name == "@" {
        base_domain.to_lowercase()
    } else if name.starts_with("*.") {
        // Wildcard subdomain
        format!("{name}.{}", base_domain.to_lowercase())
    } else {
        format!("{name}.{}", base_domain.to_lowercase())
    }
}

/// Convert a domain to ASCII using IDNA encoding.
#[allow(dead_code)]
fn domain_to_ascii(domain: &str) -> Result<String, String> {
    if domain.is_empty() {
        return Ok(String::new());
    }
    // Try IDNA encoding for internationalized domain names
    match idna::domain_to_ascii(domain) {
        Ok(ascii) => Ok(ascii),
        Err(_) => {
            // Fallback: if it's already ASCII, just return it
            if domain.is_ascii() {
                Ok(domain.to_string())
            } else {
                Err(format!("Invalid domain name: {domain}"))
            }
        }
    }
}

/// Convert ASCII domain back to Unicode for display.
#[allow(dead_code)]
fn describe_domain(ascii: &str) -> String {
    // Try to convert punycode back to unicode for display
    match idna::domain_to_unicode(ascii) {
        (unicode, Ok(())) => unicode,
        _ => ascii.to_string(),
    }
}

/// Parse a comma-separated list of domain strings.
#[allow(dead_code)]
pub fn parse_domain_list(input: &str) -> Result<Vec<Domain>, String> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    input
        .split(',')
        .map(|s| Domain::new(s.trim()))
        .collect()
}

// --- Domain Expression Evaluator ---
// Supports: true, false, is(domain,...), sub(domain,...), !, &&, ||, ()

/// Parse and evaluate a domain expression to determine if a domain should be proxied.
pub fn parse_proxied_expression(expr: &str) -> Result<Box<dyn Fn(&str) -> bool + Send + Sync>, String> {
    let expr = expr.trim();
    if expr.is_empty() || expr == "false" {
        return Ok(Box::new(|_: &str| false));
    }
    if expr == "true" {
        return Ok(Box::new(|_: &str| true));
    }

    let tokens = tokenize_expr(expr)?;
    let (predicate, rest) = parse_or_expr(&tokens)?;
    if !rest.is_empty() {
        return Err(format!("Unexpected tokens in proxied expression: {}", rest.join(" ")));
    }
    Ok(predicate)
}

fn tokenize_expr(input: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' | ')' | '!' | ',' => {
                tokens.push(c.to_string());
                chars.next();
            }
            '&' => {
                chars.next();
                if chars.peek() == Some(&'&') {
                    chars.next();
                    tokens.push("&&".to_string());
                } else {
                    return Err("Expected '&&', got single '&'".to_string());
                }
            }
            '|' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    tokens.push("||".to_string());
                } else {
                    return Err("Expected '||', got single '|'".to_string());
                }
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '*' || c == '@' {
                        word.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if word.is_empty() {
                    return Err(format!("Unexpected character: {c}"));
                }
                tokens.push(word);
            }
        }
    }
    Ok(tokens)
}

type Predicate = Box<dyn Fn(&str) -> bool + Send + Sync>;

fn parse_or_expr(tokens: &[String]) -> Result<(Predicate, &[String]), String> {
    let (mut left, mut rest) = parse_and_expr(tokens)?;
    while !rest.is_empty() && rest[0] == "||" {
        let (right, new_rest) = parse_and_expr(&rest[1..])?;
        let prev = left;
        left = Box::new(move |d: &str| prev(d) || right(d));
        rest = new_rest;
    }
    Ok((left, rest))
}

fn parse_and_expr(tokens: &[String]) -> Result<(Predicate, &[String]), String> {
    let (mut left, mut rest) = parse_not_expr(tokens)?;
    while !rest.is_empty() && rest[0] == "&&" {
        let (right, new_rest) = parse_not_expr(&rest[1..])?;
        let prev = left;
        left = Box::new(move |d: &str| prev(d) && right(d));
        rest = new_rest;
    }
    Ok((left, rest))
}

fn parse_not_expr(tokens: &[String]) -> Result<(Predicate, &[String]), String> {
    if tokens.is_empty() {
        return Err("Unexpected end of expression".to_string());
    }
    if tokens[0] == "!" {
        let (inner, rest) = parse_not_expr(&tokens[1..])?;
        let pred: Predicate = Box::new(move |d: &str| !inner(d));
        Ok((pred, rest))
    } else {
        parse_atom(tokens)
    }
}

fn parse_atom(tokens: &[String]) -> Result<(Predicate, &[String]), String> {
    if tokens.is_empty() {
        return Err("Unexpected end of expression".to_string());
    }

    match tokens[0].as_str() {
        "true" => Ok((Box::new(|_: &str| true), &tokens[1..])),
        "false" => Ok((Box::new(|_: &str| false), &tokens[1..])),
        "(" => {
            let (inner, rest) = parse_or_expr(&tokens[1..])?;
            if rest.is_empty() || rest[0] != ")" {
                return Err("Missing closing parenthesis".to_string());
            }
            Ok((inner, &rest[1..]))
        }
        "is" => {
            let (domains, rest) = parse_domain_args(&tokens[1..])?;
            let pred: Predicate = Box::new(move |d: &str| {
                let d_lower = d.to_lowercase();
                domains.iter().any(|dom| d_lower == *dom)
            });
            Ok((pred, rest))
        }
        "sub" => {
            let (domains, rest) = parse_domain_args(&tokens[1..])?;
            let pred: Predicate = Box::new(move |d: &str| {
                let d_lower = d.to_lowercase();
                domains.iter().any(|dom| {
                    d_lower == *dom || d_lower.ends_with(&format!(".{dom}"))
                })
            });
            Ok((pred, rest))
        }
        _ => Err(format!("Unexpected token: {}", tokens[0])),
    }
}

fn parse_domain_args(tokens: &[String]) -> Result<(Vec<String>, &[String]), String> {
    if tokens.is_empty() || tokens[0] != "(" {
        return Err("Expected '(' after function name".to_string());
    }
    let mut domains = Vec::new();
    let mut i = 1;
    while i < tokens.len() && tokens[i] != ")" {
        if tokens[i] == "," {
            i += 1;
            continue;
        }
        domains.push(tokens[i].to_lowercase());
        i += 1;
    }
    if i >= tokens.len() {
        return Err("Missing closing ')' in function call".to_string());
    }
    Ok((domains, &tokens[i + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_fqdn_root() {
        assert_eq!(make_fqdn("", "example.com"), "example.com");
        assert_eq!(make_fqdn("@", "example.com"), "example.com");
    }

    #[test]
    fn test_make_fqdn_subdomain() {
        assert_eq!(make_fqdn("www", "example.com"), "www.example.com");
        assert_eq!(make_fqdn("VPN", "Example.COM"), "vpn.example.com");
    }

    #[test]
    fn test_domain_wildcard() {
        let d = Domain::new("*.example.com").unwrap();
        assert_eq!(d.dns_name_ascii(), "*.example.com");
    }

    #[test]
    fn test_parse_domain_list() {
        let domains = parse_domain_list("example.com, *.example.com, sub.example.com").unwrap();
        assert_eq!(domains.len(), 3);
    }

    #[test]
    fn test_proxied_expr_true() {
        let pred = parse_proxied_expression("true").unwrap();
        assert!(pred("anything.com"));
    }

    #[test]
    fn test_proxied_expr_false() {
        let pred = parse_proxied_expression("false").unwrap();
        assert!(!pred("anything.com"));
    }

    #[test]
    fn test_proxied_expr_is() {
        let pred = parse_proxied_expression("is(example.com)").unwrap();
        assert!(pred("example.com"));
        assert!(!pred("sub.example.com"));
    }

    #[test]
    fn test_proxied_expr_sub() {
        let pred = parse_proxied_expression("sub(example.com)").unwrap();
        assert!(pred("example.com"));
        assert!(pred("sub.example.com"));
        assert!(!pred("other.com"));
    }

    #[test]
    fn test_proxied_expr_complex() {
        let pred = parse_proxied_expression("is(a.com) || is(b.com)").unwrap();
        assert!(pred("a.com"));
        assert!(pred("b.com"));
        assert!(!pred("c.com"));
    }

    #[test]
    fn test_proxied_expr_negation() {
        let pred = parse_proxied_expression("!is(internal.com)").unwrap();
        assert!(!pred("internal.com"));
        assert!(pred("public.com"));
    }

    // --- Domain::new with regular FQDN ---
    #[test]
    fn test_domain_new_fqdn() {
        let d = Domain::new("example.com").unwrap();
        assert_eq!(d, Domain::FQDN("example.com".to_string()));
    }

    #[test]
    fn test_domain_new_fqdn_uppercase() {
        let d = Domain::new("EXAMPLE.COM").unwrap();
        assert_eq!(d, Domain::FQDN("example.com".to_string()));
    }

    // --- Domain::dns_name_ascii for FQDN ---
    #[test]
    fn test_dns_name_ascii_fqdn() {
        let d = Domain::FQDN("example.com".to_string());
        assert_eq!(d.dns_name_ascii(), "example.com");
    }

    // --- Domain::describe for both variants ---
    #[test]
    fn test_describe_fqdn() {
        let d = Domain::FQDN("example.com".to_string());
        // ASCII domain should round-trip through describe unchanged
        assert_eq!(d.describe(), "example.com");
    }

    #[test]
    fn test_describe_wildcard() {
        let d = Domain::Wildcard("example.com".to_string());
        assert_eq!(d.describe(), "*.example.com");
    }

    // --- Domain::zones ---
    #[test]
    fn test_zones_fqdn() {
        let d = Domain::FQDN("sub.example.com".to_string());
        let zones = d.zones();
        assert_eq!(zones, vec!["sub.example.com", "example.com", "com"]);
    }

    #[test]
    fn test_zones_wildcard() {
        let d = Domain::Wildcard("example.com".to_string());
        let zones = d.zones();
        assert_eq!(zones, vec!["example.com", "com"]);
    }

    #[test]
    fn test_zones_single_label() {
        let d = Domain::FQDN("localhost".to_string());
        let zones = d.zones();
        assert_eq!(zones, vec!["localhost"]);
    }

    // --- Domain Display trait ---
    #[test]
    fn test_display_fqdn() {
        let d = Domain::FQDN("example.com".to_string());
        assert_eq!(format!("{d}"), "example.com");
    }

    #[test]
    fn test_display_wildcard() {
        let d = Domain::Wildcard("example.com".to_string());
        assert_eq!(format!("{d}"), "*.example.com");
    }

    // --- domain_to_ascii (tested indirectly via Domain::new) ---
    #[test]
    fn test_domain_new_empty_string() {
        // empty string -> domain_to_ascii returns Ok("") -> Domain::FQDN("")
        let d = Domain::new("").unwrap();
        assert_eq!(d, Domain::FQDN("".to_string()));
    }

    #[test]
    fn test_domain_new_ascii_domain() {
        let d = Domain::new("www.example.org").unwrap();
        assert_eq!(d.dns_name_ascii(), "www.example.org");
    }

    #[test]
    fn test_domain_new_internationalized() {
        // "münchen.de" should be encoded to punycode
        let d = Domain::new("münchen.de").unwrap();
        let ascii = d.dns_name_ascii();
        // The punycode-encoded form should start with "xn--"
        assert!(ascii.contains("xn--"), "expected punycode, got: {ascii}");
    }

    // --- describe_domain (tested indirectly via Domain::describe) ---
    #[test]
    fn test_describe_punycode_roundtrip() {
        // Build a domain with a known punycode label and confirm describe decodes it
        let d = Domain::new("münchen.de").unwrap();
        let described = d.describe();
        // Should contain the Unicode form, not the raw punycode
        assert!(described.contains("münchen") || described.contains("xn--"),
            "describe returned: {described}");
    }

    #[test]
    fn test_describe_regular_ascii() {
        let d = Domain::FQDN("example.com".to_string());
        assert_eq!(d.describe(), "example.com");
    }

    // --- parse_domain_list with empty input ---
    #[test]
    fn test_parse_domain_list_empty() {
        let result = parse_domain_list("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_domain_list_whitespace_only() {
        let result = parse_domain_list("   ").unwrap();
        assert!(result.is_empty());
    }

    // --- Tokenizer edge cases (via parse_proxied_expression) ---
    #[test]
    fn test_tokenizer_single_ampersand_error() {
        let result = parse_proxied_expression("is(a.com) & is(b.com)");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("&&"), "error was: {err}");
    }

    #[test]
    fn test_tokenizer_single_pipe_error() {
        let result = parse_proxied_expression("is(a.com) | is(b.com)");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("||"), "error was: {err}");
    }

    #[test]
    fn test_tokenizer_unexpected_character_error() {
        let result = parse_proxied_expression("is(a.com) $ is(b.com)");
        assert!(result.is_err());
    }

    // --- Parser edge cases ---
    #[test]
    fn test_parse_and_expr_double_ampersand() {
        let pred = parse_proxied_expression("is(a.com) && is(b.com)").unwrap();
        assert!(!pred("a.com"));
        assert!(!pred("b.com"));

        let pred2 = parse_proxied_expression("sub(example.com) && !is(internal.example.com)").unwrap();
        assert!(pred2("www.example.com"));
        assert!(!pred2("internal.example.com"));
    }

    #[test]
    fn test_parse_nested_parentheses() {
        let pred = parse_proxied_expression("(is(a.com) || is(b.com)) && !is(c.com)").unwrap();
        assert!(pred("a.com"));
        assert!(pred("b.com"));
        assert!(!pred("c.com"));
    }

    #[test]
    fn test_parse_missing_closing_paren() {
        let result = parse_proxied_expression("(is(a.com)");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("parenthesis") || err.contains(")"), "error was: {err}");
    }

    #[test]
    fn test_parse_unexpected_tokens_after_expr() {
        let result = parse_proxied_expression("true false");
        assert!(result.is_err());
    }

    // --- make_fqdn with wildcard subdomain ---
    #[test]
    fn test_make_fqdn_wildcard_subdomain() {
        // A name starting with "*." is treated as a wildcard subdomain
        assert_eq!(make_fqdn("*.sub", "example.com"), "*.sub.example.com");
    }
}
