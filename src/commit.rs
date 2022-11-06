use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;

pub struct Commit {
    message: String,
    hash: String,
    tags: HashSet<String>,
    fields: HashMap<String, String>,
}

impl Commit {
    pub fn new(message: &str, hash: &str) -> Commit {
        Commit {
            message: message.to_string(),
            hash: hash.to_string(),
            tags: Commit::extract_tags(message),
            fields: Commit::extract_fields(message),
        }
    }

    pub fn create_one_line_summary(&self) -> String {
        let short_hash = &self.hash[..7];
        let first_message_line = self.message.lines().next().unwrap();
        [short_hash, first_message_line].join(" ")
    }

    fn extract_tags(message: &str) -> HashSet<String> {
        lazy_static! {
            static ref TAG_RE: Regex = Regex::new(r"\[(?P<tag>[^\[\]\n\r]+)\]").unwrap();
        }

        TAG_RE
            .captures_iter(message)
            .map(|caps| caps["tag"].trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect()
    }

    fn extract_fields(message: &str) -> HashMap<String, String> {
        lazy_static! {
            static ref FIELD_RE: Regex = Regex::new(
                // The [^\S\r\n] below matches a whitespace that isn't a newline or carriage return.
                // We need that to avoid matching fields like "key: \nval".
                r"(?P<key>[^:\s\r\n]+)[^\S\r\n]*:[^\S\r\n]*(?P<val>[^:\s\r\n]+)([\r\n]*|$)"
            )
            .unwrap();
        }

        FIELD_RE
            .captures_iter(message)
            .map(|caps| (caps["key"].to_string(), caps["val"].to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let message = "[WORK IN PROGRESS] Fix wrong sorting order\n\nScope: bug-fix";
        let hash = "0123456789abcdefghij";
        let commit = Commit::new(message, hash);

        assert_eq!(commit.message, message);
        assert_eq!(commit.hash, hash);
        assert_eq!(commit.tags, HashSet::from(["WORK IN PROGRESS".to_string()]));
        assert_eq!(
            commit.fields,
            HashMap::from([("Scope".to_string(), "bug-fix".to_string())])
        );
    }

    #[test]
    fn test_create_one_line_summary() {
        let commit = Commit::new("First line\n\nSome description.\n", "0123456789abcdefghij");
        assert_eq!(commit.create_one_line_summary(), "0123456 First line");
    }

    #[test]
    fn test_extract_tags() {
        _test_extract_tags("", &[]);
        _test_extract_tags("[  ]", &[]);
        _test_extract_tags("[tag\n]", &[]);
        _test_extract_tags("[\ntag]", &[]);
        _test_extract_tags("[ta\ng]", &[]);
        _test_extract_tags("[ta\n\rg]", &[]);
        _test_extract_tags("no bracket", &[]);
        _test_extract_tags("[tag]", &["tag"]);
        _test_extract_tags("[tag][ ]", &["tag"]);
        _test_extract_tags("asd [tag] asd ", &["tag"]);
        _test_extract_tags("[tag1][tag2]", &["tag1", "tag2"]);
        _test_extract_tags("[tag1][tag1][tag2]", &["tag1", "tag2"]);
        _test_extract_tags("[tag with spaces]", &["tag with spaces"]);
        _test_extract_tags("[  tag with spaces  ]", &["tag with spaces"]);
        _test_extract_tags("[tag1]\n\r[tag2]\n[tag3]", &["tag1", "tag2", "tag3"]);
        _test_extract_tags("some text [tag1] some text [tag2]", &["tag1", "tag2"]);
    }

    fn _test_extract_tags(message: &str, expected_tags: &[&str]) {
        assert_eq!(
            Commit::extract_tags(message),
            HashSet::from(
                expected_tags
                    .iter()
                    .map(|&tag| String::from(tag))
                    .collect::<HashSet<String>>(),
            ),
            "Got left but expected right when message=\"{}\"",
            message.replace("\n", "\\n").replace("\r", "\\r")
        );
    }

    #[test]
    fn test_extract_fields() {
        let no_fields = [];
        let one_field = [("k1", "v1")];
        let two_fields = [("k1", "v1"), ("k2", "v2")];
        let three_fields = [("k1", "v1"), ("k2", "v2"), ("k3", "v3")];

        _test_extract_fields("", &no_fields);
        _test_extract_fields("k1", &no_fields);
        _test_extract_fields("k1 v1", &no_fields);
        _test_extract_fields("k1:  ", &no_fields);
        _test_extract_fields("k1 : ", &no_fields);
        _test_extract_fields("k1\n:v1", &no_fields);
        _test_extract_fields("k1:\nv1", &no_fields);
        _test_extract_fields("   :     ", &no_fields);
        _test_extract_fields("  :  :  : ", &no_fields);

        _test_extract_fields("k1:v1", &one_field);
        _test_extract_fields("k1: v1", &one_field);
        _test_extract_fields(" k1: v1", &one_field);
        _test_extract_fields(" k1  :  v1  ", &one_field);
        _test_extract_fields("k1: v1 k2:\nv2", &one_field);
        _test_extract_fields("some text k1: v1", &one_field);

        _test_extract_fields("k1: v1 k2: v2", &two_fields);
        _test_extract_fields("k1: v1\nk2: v2", &two_fields);
        _test_extract_fields("k1: v1\rk2: v2", &two_fields);
        _test_extract_fields("k1: v1\n\nk2: v2", &two_fields);
        _test_extract_fields("k1: v1\n\rk2: v2", &two_fields);
        _test_extract_fields("k1: v1 k2: v2\nv3", &two_fields);
        _test_extract_fields("k1: v1\n\r  k2: v2", &two_fields);
        _test_extract_fields("k1: v1\n\r\n\rk2: v2", &two_fields);
        _test_extract_fields(" k1: v1   k2  : v2  ", &two_fields);

        _test_extract_fields("k1:v1 k2:v2 k3:v3", &three_fields);
        _test_extract_fields("k1: v1 k2:v2 k3:v3", &three_fields);
        _test_extract_fields("k1: v1 k2:v2 k3 :v3", &three_fields);
        _test_extract_fields("k1: v1 k2:v2\nk3 :v3", &three_fields);
        _test_extract_fields("k1: v1\nk2: v2\nk3 :v3\n", &three_fields);
    }

    fn _test_extract_fields(message: &str, expected_fields: &[(&str, &str)]) {
        assert_eq!(
            Commit::extract_fields(message),
            HashMap::from(
                expected_fields
                    .iter()
                    .map(|&key_and_val| (String::from(key_and_val.0), String::from(key_and_val.1)))
                    .collect::<HashMap<String, String>>(),
            ),
            "Got left but expected right when message=\"{}\"",
            message.replace("\n", "\\n").replace("\r", "\\r")
        );
    }
}
