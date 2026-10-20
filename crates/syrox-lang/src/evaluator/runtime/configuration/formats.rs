use serde_json::{Map, Value as Data};
use std::str::FromStr as _;

pub(super) fn parse_data(format: &str, text: &str, depth: usize) -> Result<Data, String> {
    if format == "toml" {
        let document = toml_edit::DocumentMut::from_str(text).map_err(|e| e.to_string())?;
        toml_table(document.as_table(), depth)
    } else {
        let file = yaml_edit::YamlFile::from_str(text).map_err(|e| e.to_string())?;
        let documents: Vec<_> = file.documents().collect();
        if documents.len() != 1 {
            return Err("expected one YAML document".into());
        }
        let doc = &documents[0];
        let node = doc
            .as_mapping()
            .map(yaml_edit::YamlNode::Mapping)
            .or_else(|| {
                doc.as_sequence()
                    .map(yaml_edit::YamlNode::Sequence)
            })
            .or_else(|| doc.as_scalar().map(yaml_edit::YamlNode::Scalar));
        yaml_data(node.ok_or("unsupported YAML document")?, depth)
    }
}

fn yaml_data(node: yaml_edit::YamlNode, depth: usize) -> Result<Data, String> {
    if depth == 0 {
        return Err("configuration nesting limit reached".into());
    }
    match node {
        yaml_edit::YamlNode::Mapping(mapping) => {
            let mut data = Map::new();
            for (key, value) in mapping.iter() {
                let key = key
                    .as_scalar()
                    .ok_or("configuration keys must be strings")?
                    .as_string();
                if data.contains_key(&key) {
                    return Err(format!("duplicate configuration key `{key}`"));
                }
                data.insert(key, yaml_data(value, depth - 1)?);
            }
            Ok(Data::Object(data))
        }
        yaml_edit::YamlNode::Sequence(sequence) => sequence
            .values()
            .map(|n| yaml_data(n, depth - 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Data::Array),
        yaml_edit::YamlNode::Scalar(scalar) => {
            if scalar.is_null() {
                Ok(Data::Null)
            } else if let Some(value) = scalar.as_i64() {
                Ok(Data::from(value))
            } else if let Some(value) = scalar.as_bool() {
                Ok(Data::Bool(value))
            } else if let Some(value) = scalar.as_f64() {
                Ok(serde_json::Number::from_f64(value).map_or_else(
                    || unsupported_value("non-finite number"),
                    Data::Number,
                ))
            } else {
                Ok(Data::String(scalar.as_string()))
            }
        }
        _ => Ok(unsupported_value("YAML alias or tag")),
    }
}

fn toml_table(table: &toml_edit::Table, depth: usize) -> Result<Data, String> {
    if depth == 0 {
        return Err("configuration nesting limit reached".into());
    }
    table
        .iter()
        .map(|(k, v)| Ok((k.to_owned(), toml_item(v, depth - 1)?)))
        .collect::<Result<Map<_, _>, _>>()
        .map(Data::Object)
}
fn toml_item(item: &toml_edit::Item, depth: usize) -> Result<Data, String> {
    if depth == 0 {
        return Err("configuration nesting limit reached".into());
    }
    match item {
        toml_edit::Item::Value(value) => toml_data(value, depth - 1),
        toml_edit::Item::Table(table) => toml_table(table, depth - 1),
        toml_edit::Item::ArrayOfTables(tables) => tables
            .iter()
            .map(|t| toml_table(t, depth - 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Data::Array),
        toml_edit::Item::None => Ok(Data::Null),
    }
}
fn toml_data(value: &toml_edit::Value, depth: usize) -> Result<Data, String> {
    if depth == 0 {
        return Err("configuration nesting limit reached".into());
    }
    match value {
        toml_edit::Value::String(s) => Ok(Data::String(s.value().clone())),
        toml_edit::Value::Integer(i) => Ok(Data::from(*i.value())),
        toml_edit::Value::Boolean(b) => Ok(Data::Bool(*b.value())),
        toml_edit::Value::Float(f) => Ok(
            serde_json::Number::from_f64(*f.value()).map_or_else(
                || unsupported_value("non-finite number"),
                Data::Number,
            ),
        ),
        toml_edit::Value::Datetime(_) => Ok(unsupported_value("TOML datetime")),
        toml_edit::Value::Array(a) => a
            .iter()
            .map(|v| toml_data(v, depth - 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Data::Array),
        toml_edit::Value::InlineTable(t) => t
            .iter()
            .map(|(k, v)| Ok((k.to_owned(), toml_data(v, depth - 1)?)))
            .collect::<Result<Map<_, _>, _>>()
            .map(Data::Object),
    }
}
fn toml_value(data: &Data) -> Result<toml_edit::Value, String> {
    Ok(match data {
        Data::String(s) => toml_edit::Value::from(s.as_str()),
        Data::Number(n) => toml_edit::Value::from(n.as_i64().ok_or("expected integer")?),
        Data::Bool(b) => toml_edit::Value::from(*b),
        Data::Array(a) => {
            let mut array = toml_edit::Array::new();
            for v in a {
                array.push(toml_value(v)?);
            }
            array.into()
        }
        Data::Object(o) => {
            let mut table = toml_edit::InlineTable::new();
            for (k, v) in o {
                if !v.is_null() {
                    table.insert(k, toml_value(v)?);
                }
            }
            table.into()
        }
        Data::Null => return Err("TOML cannot represent None in a list or at the root".into()),
    })
}
pub(super) fn encode_data(format: &str, data: &Data) -> Result<String, String> {
    if format == "yaml" {
        if let Some(fields) = data.as_object() {
            let doc = yaml_edit::Document::new_mapping();
            let mapping = doc
                .as_mapping()
                .ok_or("missing generated mapping")?;
            for (key, value) in fields {
                mapping.set(key.as_str(), yaml_value(value)?);
            }
            return Ok(doc.to_string());
        }
        return serde_json::to_string(data)
            .map(|s| s + "\n")
            .map_err(|e| e.to_string());
    }
    let Some(fields) = data.as_object() else {
        return Err("TOML requires a record or map at the root".into());
    };
    let mut document = toml_edit::DocumentMut::new();
    for (key, value) in fields {
        if !value.is_null() {
            document[key] = toml_edit::Item::Value(toml_value(value)?);
        }
    }
    Ok(document.to_string())
}
pub(super) fn patch_data(
    format: &str,
    text: &str,
    changes: &Map<String, Data>,
) -> Result<String, String> {
    if changes.is_empty() {
        return Ok(text.to_owned());
    }
    if format == "toml" {
        let mut doc = toml_edit::DocumentMut::from_str(text).map_err(|e| e.to_string())?;
        for (key, data) in changes {
            if data.is_null() {
                doc.remove(key);
                continue;
            }
            let mut value = toml_value(data)?;
            if let Some(old) = doc.get(key).and_then(toml_edit::Item::as_value) {
                *value.decor_mut() = old.decor().clone();
            }
            doc[key] = toml_edit::Item::Value(value);
        }
        Ok(doc.to_string())
    } else {
        let file = yaml_edit::YamlFile::from_str(text).map_err(|e| e.to_string())?;
        let doc = file
            .documents()
            .next()
            .ok_or("missing YAML document")?;
        let mapping = doc
            .as_mapping()
            .ok_or("patch requires a YAML mapping")?;
        for (key, data) in changes {
            mapping.set(key.as_str(), yaml_value(data)?);
        }
        Ok(file.to_string())
    }
}

pub(super) fn prune_absent_options(data: &mut Data) {
    match data {
        Data::Object(fields) => {
            fields.retain(|_, value| !value.is_null());
            for value in fields.values_mut() {
                prune_absent_options(value);
            }
        }
        Data::Array(items) => {
            for item in items {
                prune_absent_options(item);
            }
        }
        _ => {}
    }
}

// Preserve unknown syntax in documents while refusing it when a typed field is read.
fn unsupported_value(kind: &str) -> Data {
    let mut marker = Map::new();
    marker.insert(
        "\0unsupported-config-value".into(),
        Data::String(kind.into()),
    );
    Data::Object(marker)
}

fn yaml_value(data: &Data) -> Result<yaml_edit::YamlNode, String> {
    // Quoted JSON scalars and flow collections are valid YAML, including strings
    // such as "yes", numeric-looking labels, newlines and literal backslashes.
    let text = serde_json::to_string(data).map_err(|error| error.to_string())?;
    let file = yaml_edit::YamlFile::from_str(&text).map_err(|error| error.to_string())?;
    let doc = file
        .documents()
        .next()
        .ok_or("missing YAML value")?;
    doc.as_scalar()
        .map(yaml_edit::YamlNode::Scalar)
        .or_else(|| {
            doc.as_sequence()
                .map(yaml_edit::YamlNode::Sequence)
        })
        .or_else(|| doc.as_mapping().map(yaml_edit::YamlNode::Mapping))
        .ok_or_else(|| "unsupported YAML value".to_owned())
}
