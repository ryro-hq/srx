//! Literal encoding for configuration fuzz inputs embedded in srx source.
pub fn configuration_literal(text: &str) -> String {
    let mut literal = String::from("\"");
    for character in text.chars() {
        match character {
            '"' => literal.push_str("\\\""),
            '\\' => literal.push_str("\\\\"),
            '$' => literal.push_str("\\$"),
            '\n' => literal.push_str("\\n"),
            '\r' => literal.push_str("\\r"),
            '\t' => literal.push_str("\\t"),
            other => literal.push(other),
        }
    }
    literal.push('"');
    literal
}

#[cfg(test)]
mod tests {
    use super::*;
    use syrox_lang::{source::Source, syntax::analyze};

    #[test]
    fn control_and_unicode_inputs_remain_valid_srx_source() {
        let controls: String = (0..=127).map(char::from).collect();
        for text in [
            "\u{b}",
            controls.as_str(),
            "${input} \\\" unicode: 日本 🦀",
        ] {
            let literal = configuration_literal(text);
            let source = Source::new("main.srx", format!("let input = {literal};")).unwrap();
            analyze(&source).expect("fuzz wrapper must accept arbitrary UTF-8 input");
        }
    }
}
