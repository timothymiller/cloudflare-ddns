/// Construct an FQDN from a subdomain name and base domain.
pub fn make_fqdn(subdomain: &str, base_domain: &str) -> String {
    let name = subdomain.to_lowercase();
    let name = name.trim();
    if name.is_empty() || name == "@" {
        base_domain.to_lowercase()
    } else {
        format!("{name}.{}", base_domain.to_lowercase())
    }
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

    #[test]
    fn test_make_fqdn_wildcard_subdomain() {
        assert_eq!(make_fqdn("*.sub", "example.com"), "*.sub.example.com");
    }
}
