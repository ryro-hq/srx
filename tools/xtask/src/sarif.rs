//! Fail closed on unsuccessful analysis and high/critical security results.
use super::{Result, files};
use serde_json::Value;
use std::{fs, path::Path};

pub(super) fn check(directory: &Path, language: &str) -> Result {
    if !matches!(language, "rust" | "actions") {
        return Err("unexpected analysis language".into());
    }
    let mut reports = Vec::new();
    files(directory, ".sarif", &mut reports)?;
    if reports.is_empty() {
        return Err("analysis produced no SARIF reports".into());
    }
    for report in reports {
        let metadata = fs::metadata(&report)?;
        if metadata.len() > 64 * 1024 * 1024 {
            return Err("oversized SARIF report".into());
        }
        let document: Value = serde_json::from_slice(&fs::read(&report)?)?;
        validate(&document)?;
    }
    println!("CodeQL {language}: analysis succeeded; no high/critical findings");
    Ok(())
}

fn validate(document: &Value) -> Result {
    if document["version"] != "2.1.0" {
        return Err("unsupported SARIF version".into());
    }
    let runs = document["runs"]
        .as_array()
        .filter(|r| !r.is_empty())
        .ok_or("missing analysis runs")?;
    for run in runs {
        if !run["tool"]["driver"]["name"]
            .as_str()
            .is_some_and(|name| name.contains("CodeQL"))
        {
            return Err("expected CodeQL analysis".into());
        }
        let invocations = run["invocations"]
            .as_array()
            .filter(|r| !r.is_empty())
            .ok_or("missing analysis invocation")?;
        for invocation in invocations {
            if invocation["executionSuccessful"] != true {
                return Err("analysis failed".into());
            }
            for field in [
                "toolExecutionNotifications",
                "toolConfigurationNotifications",
            ] {
                if let Some(notifications) = invocation[field].as_array()
                    && notifications
                        .iter()
                        .any(|notice| notice["level"] == "error")
                {
                    return Err("analysis reported an error".into());
                }
            }
        }
        let rules = run["tool"]["driver"]["rules"]
            .as_array()
            .ok_or("missing analysis rules")?;
        let results = run["results"]
            .as_array()
            .ok_or("missing analysis results")?;
        for result in results {
            let id = result["ruleId"]
                .as_str()
                .ok_or("finding lacks ruleId")?;
            let rule = if let Some(index) = result["ruleIndex"].as_u64() {
                let index = usize::try_from(index)?;
                rules.get(index).filter(|rule| rule["id"] == id)
            } else {
                rules.iter().find(|rule| rule["id"] == id)
            }
            .ok_or("finding references an unknown rule")?;
            let raw = &rule["properties"]["security-severity"];
            let severity = match raw {
                Value::Null => None,
                Value::String(value) => Some(value.parse::<f64>()?),
                Value::Number(value) => Some(value.as_f64().ok_or("invalid severity")?),
                _ => return Err("invalid security severity".into()),
            };
            if let Some(severity) = severity {
                if !severity.is_finite() || !(0.0..=10.0).contains(&severity) {
                    return Err("invalid security severity".into());
                }
                // Inline SARIF suppression cannot weaken this gate. Exceptions need
                // separate, reviewed policy with expiry before they are supported.
                if severity >= 7.0 {
                    return Err(format!("high/critical CodeQL finding: {id} ({severity})").into());
                }
            } else if result["level"] == "error"
                || rule["properties"]["tags"]
                    .as_array()
                    .is_some_and(|tags| tags.iter().any(|tag| tag == "security"))
            {
                return Err(format!("CodeQL finding with unknown security severity: {id}").into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn document(severity: &str) -> Value {
        json!({"version":"2.1.0", "runs":[{"tool":{"driver":{"name":"CodeQL", "rules":[{"id":"injection", "properties":{"security-severity":severity}}]}}, "invocations":[{"executionSuccessful":true}], "results":[{"ruleId":"injection", "ruleIndex":0}]}]})
    }
    #[test]
    fn security_failures_block_including_queue_and_suppressions() {
        for severity in ["7.0", "9.8", "NaN", "broken", "-1"] {
            assert!(validate(&document(severity)).is_err());
        }
        assert!(validate(&document("6.9")).is_ok());
        let mut value = document("8.0");
        value["runs"][0]["results"][0]["suppressions"] = json!([{"status":"accepted"}]);
        assert!(validate(&value).is_err());
        value["runs"][0]["results"] = json!([]);
        value["runs"][0]["invocations"][0]["executionSuccessful"] = json!(false);
        assert!(validate(&value).is_err());
        assert!(validate(&json!({"version":"2.1.0", "runs":[]})).is_err());
        let mut value = document("1.0");
        value["runs"][0]["results"][0]["ruleIndex"] = json!(55);
        assert!(validate(&value).is_err());
        let mut value = document("1.0");
        value["runs"][0]["tool"]["driver"]["rules"][0]["properties"] = json!({"tags":["security"]});
        assert!(validate(&value).is_err());
    }
}
