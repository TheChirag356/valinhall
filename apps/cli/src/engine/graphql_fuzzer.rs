//! GraphQL Fuzzer Engine
//!
//! Modules to specifically test GraphQL endpoints for:
//! - Introspection Exposure
//! - Circular Queries
//! - Deep Nesting attacks

use reqwest::Client;
use std::time::Duration;
use uuid::Uuid;
use crate::models::{Finding, FindingSource, OwaspCategory, Severity};

pub async fn run_checks(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    // Quick heuristic: run a basic `__typename` query to see if it responds like GraphQL.
    let probe_body = r#"{"query":"{ __typename }"}"#;
    let resp = match client.post(url).header("Content-Type", "application/json").body(probe_body).timeout(tout).send().await {
        Ok(r) => r,
        Err(_) => return findings,
    };
    
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return findings,
    };
    
    // If it doesn't look like a GraphQL response, skip it
    if !text.contains("__typename") && !text.contains("data") && !text.contains("errors") {
        return findings;
    }
    
    // We found a likely GraphQL endpoint, proceed with fuzzer checks.
    findings.extend(check_introspection(client, url, tout).await);
    findings.extend(check_circular_queries(client, url, tout).await);
    findings.extend(check_deep_nesting(client, url, tout).await);
    
    findings
}

async fn check_introspection(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    let intro_query = r#"{"query":"\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n      }\n    }\n  "}"#;
    
    if let Ok(resp) = client.post(url).header("Content-Type", "application/json").body(intro_query).timeout(tout).send().await {
        if let Ok(text) = resp.text().await {
            if text.contains("__schema") && text.contains("queryType") {
                return vec![Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::SecurityMisconfiguration,
                    severity: Severity::High,
                    title: "[GraphQL] Introspection Enabled".to_string(),
                    description: format!("The GraphQL endpoint `{}` has introspection enabled. An attacker can query the `__schema` field to map out the entire database structure, including sensitive types, mutations, and fields.", url),
                    evidence: Some(format!("Introspection query returned schema data: {}", &text[..200.min(text.len())])),
                    remediation: "Disable GraphQL introspection in production environments. Only enable it for development/staging.".to_string(),
                    source: FindingSource::GraphqlFuzzer,
                    endpoint: Some(url.to_string()),
                }];
            }
        }
    }
    vec![]
}

async fn check_circular_queries(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    // Send a mutually recursive fragment to check if the server is vulnerable to Fragment Cycles DoS
    let fragment_cycle = r#"{"query":"fragment A on Query { __typename ...B } fragment B on Query { __typename ...A } query { ...A }"}"#;
    
    if let Ok(resp) = client.post(url).header("Content-Type", "application/json").body(fragment_cycle).timeout(tout).send().await {
        let status = resp.status().as_u16();
        if let Ok(text) = resp.text().await {
            // A properly configured server returns a validation error for cyclic fragments.
            // A vulnerable server might return 500, crash, or explicitly complain about "stack level too deep".
            if status >= 500 || text.contains("stack level too deep") || text.contains("Maximum call stack size exceeded") {
                return vec![Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::InsecureDesign,
                    severity: Severity::High,
                    title: "[GraphQL] Fragment Cycle / Circular Query DoS".to_string(),
                    description: format!("The GraphQL endpoint `{}` appears vulnerable to Fragment Cycles. Sending mutually recursive fragments caused a server error (Status {}), indicating a lack of circular reference protection.", url, status),
                    evidence: Some(format!("Payload: {}\nResponse snippet: {}", fragment_cycle, &text[..200.min(text.len())])),
                    remediation: "Ensure the GraphQL engine detects and rejects cyclic fragment spreads before execution.".to_string(),
                    source: FindingSource::GraphqlFuzzer,
                    endpoint: Some(url.to_string()),
                }];
            }
        }
    }
    vec![]
}

async fn check_deep_nesting(client: &Client, url: &str, tout: Duration) -> Vec<Finding> {
    // Try to send an extremely deep aliased query to test for Query Depth Limiting
    // Using introspection fields since they exist if introspection is enabled, otherwise parser handles it
    let deep_query = r#"{"query":"query { __schema { queryType { fields { type { fields { type { fields { type { fields { type { fields { type { fields { type { fields { type { name } } } } } } } } } } } } } } } } }"}"#;
    
    if let Ok(resp) = client.post(url).header("Content-Type", "application/json").body(deep_query).timeout(tout).send().await {
        if let Ok(text) = resp.text().await {
            // If the server processes it successfully without error
            if text.contains("__schema") && text.contains("data") && !text.contains("depth limit") && !text.contains("syntax error") && !text.contains("Validation error") && !text.contains("Cannot query field") {
                return vec![Finding {
                    id: Uuid::new_v4().to_string(),
                    category: OwaspCategory::InsecureDesign,
                    severity: Severity::Medium,
                    title: "[GraphQL] Deep Nesting Allowed (Missing Depth Limit)".to_string(),
                    description: format!("The GraphQL endpoint `{}` successfully processed an extremely deep query. This indicates a lack of Query Depth Limiting, making the server susceptible to Resource Exhaustion (DoS) attacks.", url),
                    evidence: Some(format!("Successfully executed deeply nested query.\nResponse snippet: {}", &text[..200.min(text.len())])),
                    remediation: "Implement a Maximum Query Depth limit (e.g. max depth of 5-10) using tools like `graphql-depth-limit` to prevent DoS from maliciously nested queries.".to_string(),
                    source: FindingSource::GraphqlFuzzer,
                    endpoint: Some(url.to_string()),
                }];
            }
        }
    }
    vec![]
}
