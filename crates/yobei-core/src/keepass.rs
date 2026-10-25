//! KeePass XML import (the KeePass 2.x / KeePassXC export format).
//!
//! Entries are `<String>` key/value pairs inside nested `<Group>`s.
//! Group paths become tags. Standard keys map to the account model;
//! anything else is preserved as a custom field — including KeePassXC's
//! TOTP attributes (`TOTP Seed` / `TOTP Settings`) and KeePass2Android's
//! `otp` field, which become a real [`TotpConfig`].

use crate::record::{Field, FieldKind, Record, TotpConfig};
use crate::transfer;

pub fn parse_keepass_xml(text: &str) -> Result<Vec<Record>, String> {
    let doc = roxmltree::Document::parse(text)
        .map_err(|e| format!("parse KeePass XML: {e}"))?;
    let mut out = Vec::new();
    for node in doc.descendants() {
        if node.tag_name().name() == "Entry" {
            if let Some(record) = parse_entry(node) {
                out.push(record);
            }
        }
    }
    if out.is_empty() {
        return Err("no entries found in KeePass XML".to_string());
    }
    Ok(out)
}

fn string_value(entry: roxmltree::Node, key: &str) -> Option<String> {
    for string_node in entry.children().filter(|n| n.tag_name().name() == "String") {
        let mut k: Option<String> = None;
        let mut v: Option<String> = None;
        for child in string_node.children() {
            match child.tag_name().name() {
                "Key" => k = child.text().map(|s| s.to_string()),
                "Value" => v = child.text().map(|s| s.to_string()),
                _ => {}
            }
        }
        if k.as_deref() == Some(key) {
            return v.filter(|s| !s.is_empty());
        }
    }
    None
}

fn all_strings(entry: roxmltree::Node) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for string_node in entry.children().filter(|n| n.tag_name().name() == "String") {
        let mut k = String::new();
        let mut v = String::new();
        for child in string_node.children() {
            match child.tag_name().name() {
                "Key" => k = child.text().unwrap_or("").to_string(),
                "Value" => v = child.text().unwrap_or("").to_string(),
                _ => {}
            }
        }
        if !k.is_empty() {
            out.push((k, v));
        }
    }
    out
}

fn group_path(entry: roxmltree::Node) -> Vec<String> {
    let mut groups = Vec::new();
    let mut current = entry.parent();
    while let Some(node) = current {
        if node.tag_name().name() == "Group" {
            if let Some(name) = node
                .children()
                .find(|n| n.tag_name().name() == "Name")
                .and_then(|n| n.text())
            {
                if !name.is_empty() {
                    groups.push(name.to_string());
                }
            }
        }
        current = node.parent();
    }
    groups.reverse();
    groups
}

fn parse_entry(entry: roxmltree::Node) -> Option<Record> {
    let title = string_value(entry, "Title")?;
    let username = string_value(entry, "UserName").unwrap_or_default();
    let password = string_value(entry, "Password").unwrap_or_default();
    let url = string_value(entry, "URL").unwrap_or_default();
    let notes = string_value(entry, "Notes").unwrap_or_default();

    let mut totp: Option<TotpConfig> = None;
    let mut totp_seed: Option<String> = None;
    let mut fields: Vec<Field> = Vec::new();
    const STANDARD: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];
    for (key, value) in all_strings(entry) {
        if STANDARD.contains(&key.as_str()) || value.is_empty() {
            continue;
        }
        let lower = key.to_lowercase();
        if lower == "otp" {
            totp = transfer::parse_totp_value(&value).or(totp);
        } else if lower.contains("totp") && lower.contains("seed") {
            totp_seed = Some(value.clone());
        } else if lower.contains("totp") && lower.contains("setting") {
            // "TOTP Settings" (e.g. "30;6") tunes period/digits; applied
            // after the loop once the seed is known.
            fields.push(Field {
                name: key,
                kind: FieldKind::Text,
                value,
            });
        } else {
            fields.push(Field {
                name: key,
                kind: FieldKind::Text,
                value,
            });
        }
    }
    if totp.is_none() {
        if let Some(seed) = totp_seed {
            totp = transfer::parse_totp_value(&seed);
        }
    }

    let mut record = transfer::account_record(
        title,
        &username,
        &password,
        vec![url],
        totp,
        &notes,
    );
    record.fields = fields;
    record.tags = group_path(entry);
    Some(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RecordKind;

    const KEEPASS_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Root>
  <Group><Name>Internet</Name>
    <Entry>
      <String><Key>Title</Key><Value>GitHub</Value></String>
      <String><Key>UserName</Key><Value>octocat</Value></String>
      <String><Key>Password</Key><Value>hunter2</Value></String>
      <String><Key>URL</Key><Value>https://github.com</Value></String>
      <String><Key>Notes</Key><Value>main</Value></String>
      <String><Key>TOTP Seed</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
      <String><Key>Recovery</Key><Value>code-123</Value></String>
    </Entry>
    <Group><Name>Email</Name>
      <Entry>
        <String><Key>Title</Key><Value>Fastmail</Value></String>
        <String><Key>UserName</Key><Value>me@fastmail.com</Value></String>
        <String><Key>Password</Key><Value>pw</Value></String>
      </Entry>
    </Group>
  </Group>
</Root></KeePassFile>"#;

    #[test]
    fn keepass_entries_groups_and_totp_seed() {
        let records = parse_keepass_xml(KEEPASS_XML).unwrap();
        assert_eq!(records.len(), 2);
        let gh = &records[0];
        assert_eq!(gh.kind, RecordKind::Account);
        assert_eq!(gh.tags, vec!["Internet"]);
        let acct = gh.account.as_ref().unwrap();
        assert_eq!(acct.username, "octocat");
        assert!(acct.totp.is_some());
        assert!(gh
            .fields
            .iter()
            .any(|f| f.name == "Recovery" && f.value == "code-123"));
        assert_eq!(records[1].tags, vec!["Internet", "Email"]);
    }
}
