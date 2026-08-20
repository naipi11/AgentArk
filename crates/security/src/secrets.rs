use regex::Regex;
use serde::Serialize;

use crate::SecurityError;

const RULE_VERSION: &str = "agentark-secret-rules-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretClass {
    PrivateKey,
    Authorization,
    StructuredValue,
    UriUserInfo,
    VendorToken,
}

impl SecretClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::PrivateKey => "private-key",
            Self::Authorization => "authorization",
            Self::StructuredValue => "structured-value",
            Self::UriUserInfo => "uri-user-info",
            Self::VendorToken => "vendor-token",
        }
    }
}

struct Rule {
    pattern: Regex,
    class: SecretClass,
}

pub struct SecretScanner {
    rules: Vec<Rule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretFinding {
    pub class: SecretClass,
    pub rule_version: &'static str,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedText {
    pub text: String,
    pub findings: Vec<SecretFinding>,
}

impl SecretScanner {
    pub fn v1() -> Result<Self, SecurityError> {
        let definitions = [
            (
                r"(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                SecretClass::PrivateKey,
            ),
            (
                r"(?im)^(authorization|cookie)\s*:\s*[^\r\n]+",
                SecretClass::Authorization,
            ),
            (
                r#"(?i)["']?(token|access_token|refresh_token|api_key|secret|password|authorization)["']?\s*[:=]\s*"(?:\\.|[^"\\])*""#,
                SecretClass::StructuredValue,
            ),
            (
                r#"(?i)["']?(token|access_token|refresh_token|api_key|secret|password|authorization)["']?\s*[:=]\s*'(?:\\.|[^'\\])*'"#,
                SecretClass::StructuredValue,
            ),
            (
                r#"(?i)["']?(token|access_token|refresh_token|api_key|secret|password|authorization)["']?\s*[:=]\s*[^\s"',}]+"#,
                SecretClass::StructuredValue,
            ),
            (
                r"(?i)https?://[^/\s:@]+:[^@\s/]+@",
                SecretClass::UriUserInfo,
            ),
            (r"\bsk-[A-Za-z0-9_-]{20,}\b", SecretClass::VendorToken),
            (r"\bghp_[A-Za-z0-9]{20,}\b", SecretClass::VendorToken),
            (
                r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
                SecretClass::VendorToken,
            ),
            (r"\bAKIA[0-9A-Z]{16}\b", SecretClass::VendorToken),
        ];
        let mut rules = Vec::with_capacity(definitions.len());
        for (pattern, class) in definitions {
            rules.push(Rule {
                pattern: Regex::new(pattern).map_err(|_| SecurityError::SecretRuleInvalid)?,
                class,
            });
        }
        Ok(Self { rules })
    }

    pub fn sanitize(&self, input: &str) -> SanitizedText {
        let mut candidates = self
            .rules
            .iter()
            .flat_map(|rule| {
                rule.pattern
                    .find_iter(input)
                    .map(move |matched| (matched.start(), matched.end(), rule.class))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(start, end, _)| (*start, std::cmp::Reverse(*end)));

        let mut accepted = Vec::new();
        let mut last_end = 0;
        for (start, end, class) in candidates {
            if start >= last_end {
                accepted.push((start, end, class));
                last_end = end;
            }
        }

        let mut output = String::with_capacity(input.len());
        let mut findings = Vec::with_capacity(accepted.len());
        let mut cursor = 0;
        for (start, end, class) in accepted {
            output.push_str(&input[cursor..start]);
            output.push_str("[REDACTED:");
            output.push_str(class.label());
            output.push(']');
            findings.push(SecretFinding {
                class,
                rule_version: RULE_VERSION,
                start,
                end,
            });
            cursor = end;
        }
        output.push_str(&input[cursor..]);
        SanitizedText {
            text: output,
            findings,
        }
    }
}
