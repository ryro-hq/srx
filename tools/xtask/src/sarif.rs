//! Fail closed on unsuccessful analysis and high/critical security results.
use super::{Result, files};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
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
    let exceptions = load_exceptions()?;
    for report in reports {
        let metadata = fs::metadata(&report)?;
        if metadata.len() > 64 * 1024 * 1024 {
            return Err("oversized SARIF report".into());
        }
        let document: Value = serde_json::from_slice(&fs::read(&report)?)?;
        if !document["runs"].as_array().is_some_and(|runs| {
            runs.iter().any(|run| {
                run["tool"]["extensions"]
                    .as_array()
                    .is_some_and(|extensions| {
                        extensions.iter().any(|component| {
                            component["name"] == format!("codeql/{language}-queries")
                        })
                    })
            })
        }) {
            return Err("SARIF lacks the expected CodeQL language query pack".into());
        }
        validate_with(&document, &exceptions)?;
    }
    println!("CodeQL {language}: analysis succeeded; no unreviewed high/critical findings");
    Ok(())
}

#[cfg(test)]
fn validate(document: &Value) -> Result {
    validate_with(document, &[])
}
fn validate_with(document: &Value, exceptions: &[Value]) -> Result {
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
        let results = run["results"]
            .as_array()
            .ok_or("missing analysis results")?;
        for result in results {
            let id = result["ruleId"]
                .as_str()
                .ok_or("finding lacks ruleId")?;
            let rule = resolve_rule(run, result, id)?;
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
                    if !excepted(result, id, exceptions) {
                        return Err(
                            format!("high/critical CodeQL finding: {id} ({severity})").into(),
                        );
                    }
                    println!(
                        "Reviewed CodeQL exception: {id} at {}:{}",
                        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                        result["locations"][0]["physicalLocation"]["region"]["startLine"]
                    );
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

// SARIF query packs place their rules in tool.extensions, with an explicit
// toolComponent/index reference. Never resolve an invalid reference by fallback.
fn resolve_rule<'a>(run: &'a Value, result: &Value, id: &str) -> Result<&'a Value> {
    let component = &result["rule"]["toolComponent"];
    let driver = &run["tool"]["driver"];
    let selected = if component.is_null() {
        driver
    } else if let Some(index) = component["index"].as_u64() {
        let index = usize::try_from(index)?;
        run["tool"]["extensions"]
            .as_array()
            .and_then(|extensions| extensions.get(index))
            .ok_or("finding references an unknown tool component")?
    } else {
        return Err("finding lacks a tool component index".into());
    };
    for field in ["name", "guid"] {
        if !component[field].is_null() && component[field] != selected[field] {
            return Err("tool component identity mismatch".into());
        }
    }
    if !result["rule"]["id"].is_null() && result["rule"]["id"] != id {
        return Err("conflicting finding rule identity".into());
    }
    let rules = selected["rules"]
        .as_array()
        .ok_or("missing component rules")?;
    let direct = &result["ruleIndex"];
    let indirect = &result["rule"]["index"];
    if !direct.is_null() && !indirect.is_null() && direct != indirect {
        return Err("conflicting finding rule indices".into());
    }
    let index = if direct.is_null() {
        indirect
    } else {
        direct
    };
    if index.is_null() {
        let mut matches = rules.iter().filter(|rule| rule["id"] == id);
        let rule = matches
            .next()
            .ok_or("finding references an unknown rule")?;
        if matches.next().is_some() {
            return Err("ambiguous rule identity".into());
        }
        Ok(rule)
    } else {
        let index = usize::try_from(index.as_u64().ok_or("invalid rule index")?)?;
        rules
            .get(index)
            .filter(|rule| rule["id"] == id)
            .ok_or_else(|| "finding references an unknown rule".into())
    }
}

pub(super) fn exceptions() -> Result {
    load_exceptions().map(|_| ())
}

fn load_exceptions() -> Result<Vec<Value>> {
    let policy: Value = serde_json::from_slice(&fs::read("security/codeql-exceptions.json")?)?;
    if policy["schema"] != 1 {
        return Err("unsupported CodeQL exception schema".into());
    }
    let records = policy["exceptions"]
        .as_array()
        .ok_or("missing CodeQL exception records")?;
    if records.len() > 128 {
        return Err("too many CodeQL exceptions".into());
    }
    let today = super::policy::today()?;
    let mut seen = std::collections::BTreeSet::new();
    for record in records {
        for field in [
            "rule_id",
            "fingerprint",
            "path",
            "source_sha256",
            "owner",
            "reviewed_by",
            "reason",
            "expires",
        ] {
            if record[field]
                .as_str()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(format!(
                    "CodeQL exception lacks {field}; maintainer review is required"
                )
                .into());
            }
        }
        let expiry = record["expires"]
            .as_str()
            .ok_or("missing expiry")?;
        if !super::policy::unexpired(expiry, &today)
            || record["reason"]
                .as_str()
                .is_none_or(|reason| reason.len() < 30)
        {
            return Err("expired or unexplained CodeQL exception".into());
        }
        let path = Path::new(
            record["path"]
                .as_str()
                .ok_or("missing source path")?,
        );
        if !path
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
        {
            return Err("unsafe CodeQL exception source path".into());
        }
        let mut checked = std::path::PathBuf::new();
        for part in path.components() {
            checked.push(part);
            if fs::symlink_metadata(&checked)?.is_symlink() {
                return Err("symlink in exception source".into());
            }
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
            return Err("invalid exception source file".into());
        }
        let bytes = fs::read(path)?;
        if record["source_sha256"] != format!("{:x}", Sha256::digest(&bytes)) {
            return Err("CodeQL exception source changed; review again".into());
        }
        let line = record["line"]
            .as_u64()
            .filter(|line| *line > 0)
            .ok_or("invalid exception line")?;
        let key = (
            record["rule_id"].to_string(),
            record["path"].to_string(),
            record["fingerprint"].to_string(),
            line,
        );
        if !seen.insert(key) {
            return Err("duplicate CodeQL exception".into());
        }
    }
    // Bind the reviewed flows to the full runtime source/dependency context.
    if !records.is_empty() && policy["source_tree_sha256"] != source_context()? {
        return Err("CodeQL exception runtime context changed; review again".into());
    }
    Ok(records.clone())
}

fn source_context() -> Result<String> {
    let mut paths = vec!["Cargo.lock".into(), "Cargo.toml".into()];
    for directory in ["crates", "std"] {
        for suffix in [".rs", ".toml", ".srx"] {
            files(Path::new(directory), suffix, &mut paths)?;
        }
    }
    paths.sort();
    let mut hash = Sha256::new();
    let mut total = 0;
    for path in paths {
        let bytes = fs::read(&path)?;
        total += bytes.len();
        if total > 64 * 1024 * 1024 {
            return Err("exception source context exceeds limit".into());
        }
        hash.update(
            path.to_str()
                .ok_or("non-UTF-8 context path")?
                .as_bytes(),
        );
        hash.update([0]);
        hash.update(u64::try_from(bytes.len())?.to_le_bytes());
        hash.update(bytes);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn excepted(result: &Value, id: &str, records: &[Value]) -> bool {
    let Some(locations) = result["locations"]
        .as_array()
        .filter(|locations| locations.len() == 1)
    else {
        return false;
    };
    let location = &locations[0]["physicalLocation"];
    let fingerprint = &result["partialFingerprints"]["primaryLocationLineHash"];
    !fingerprint.is_null()
        && records.iter().any(|record| {
            record["rule_id"] == id
                && record["path"] == location["artifactLocation"]["uri"]
                && record["line"] == location["region"]["startLine"]
                && record["fingerprint"] == *fingerprint
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn document(severity: &str) -> Value {
        json!({"version":"2.1.0", "runs":[{"tool":{"driver":{"name":"CodeQL", "rules":[{"id":"injection", "properties":{"security-severity":severity}}]}}, "invocations":[{"executionSuccessful":true}], "results":[{"ruleId":"injection", "ruleIndex":0}]}]})
    }
    #[test]
    fn reviewed_exceptions_match_only_the_exact_finding() {
        let mut value = document("9.8");
        value["runs"][0]["results"][0]["locations"] = json!([{"physicalLocation":{"artifactLocation":{"uri":"src.rs"},"region":{"startLine":12}}}]);
        value["runs"][0]["results"][0]["partialFingerprints"] =
            json!({"primaryLocationLineHash":"abc:1"});
        let records =
            [json!({"rule_id":"injection","path":"src.rs","line":12,"fingerprint":"abc:1"})];
        validate_with(&value, &records).unwrap();
        value["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"] =
            json!("different:1");
        assert!(validate_with(&value, &records).is_err());
        value["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"] =
            json!("abc:1");
        value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] =
            json!(13);
        assert!(validate_with(&value, &records).is_err());
    }
    #[test]
    fn query_pack_rules_preserve_the_security_gate() {
        let mut value = document("8.0");
        let rules = value["runs"][0]["tool"]["driver"]["rules"].take();
        value["runs"][0]["tool"]["driver"]["rules"] = json!([]);
        value["runs"][0]["tool"]["extensions"] =
            json!([{"name":"codeql/rust-queries","rules":rules}]);
        value["runs"][0]["results"][0] = json!({"ruleId":"injection","rule":{"id":"injection","index":0,"toolComponent":{"index":0}}});
        assert!(
            validate(&value)
                .unwrap_err()
                .to_string()
                .contains("high/critical")
        );
        value["runs"][0]["tool"]["extensions"][0]["rules"][0]["properties"]["security-severity"] =
            json!("1.0");
        validate(&value).unwrap();
        value["runs"][0]["results"][0]["rule"]["toolComponent"]["index"] = json!(1);
        assert!(validate(&value).is_err());
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
