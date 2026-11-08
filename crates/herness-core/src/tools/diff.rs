//! Deterministic, bounded line diff for persisted file changes.

use serde::{Deserialize, Serialize};

/// Maximum UTF-8 bytes kept in one persisted diff.
pub const MAX_DIFF_BYTES: usize = 32 * 1024;

/// Number of unchanged context lines kept before and after a changed block.
const CONTEXT_LINES: usize = 3;

/// A textual line diff plus an explicit truncation flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileDiff {
    text: String,
    truncated: bool,
}

impl FileDiff {
    /// Empty diff for a no-op or unavailable comparison.
    pub fn empty() -> Self {
        Self {
            text: String::new(),
            truncated: false,
        }
    }

    /// Diff text. When truncated, the text ends with an explicit marker.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether the persisted text was cut off.
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// Produces a unified-style diff with one common-prefix/common-suffix block.
///
/// The implementation is intentionally simple and deterministic: it trims the
/// shared prefix and suffix and emits at most three context lines around the
/// changed block. It is not a minimal edit script, but it is stable and shows
/// every changed line.
pub fn line_diff(old: &str, new: &str, label: &str) -> FileDiff {
    let old_lines: Vec<&str> = old.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = new.split_inclusive('\n').collect();

    let mut prefix = 0;
    while prefix < old_lines.len()
        && prefix < new_lines.len()
        && old_lines[prefix] == new_lines[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < old_lines.len().saturating_sub(prefix)
        && suffix < new_lines.len().saturating_sub(prefix)
        && old_lines[old_lines.len() - 1 - suffix] == new_lines[new_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let old_middle = &old_lines[prefix..old_lines.len() - suffix];
    let new_middle = &new_lines[prefix..new_lines.len() - suffix];
    if old_middle.is_empty() && new_middle.is_empty() {
        return FileDiff::empty();
    }

    let context_start = prefix.saturating_sub(CONTEXT_LINES);
    let suffix_context = CONTEXT_LINES.min(suffix);
    let old_context_end = prefix + old_middle.len() + suffix_context;
    let new_context_end = prefix + new_middle.len() + suffix_context;

    let mut output = String::new();
    output.push_str(&format!("--- a/{label}\n"));
    output.push_str(&format!("+++ b/{label}\n"));
    let old_start = if old_lines.is_empty() {
        0
    } else {
        context_start + 1
    };
    let new_start = if new_lines.is_empty() {
        0
    } else {
        context_start + 1
    };
    output.push_str(&format!(
        "@@ -{},{} +{},{} @@\n",
        old_start,
        old_context_end.saturating_sub(context_start),
        new_start,
        new_context_end.saturating_sub(context_start)
    ));

    for line in &old_lines[context_start..prefix] {
        push_line(&mut output, ' ', line);
    }
    for line in old_middle {
        push_line(&mut output, '-', line);
    }
    for line in new_middle {
        push_line(&mut output, '+', line);
    }
    let suffix_start = old_lines.len() - suffix;
    for line in &old_lines[suffix_start..suffix_start + suffix_context] {
        push_line(&mut output, ' ', line);
    }

    FileDiff::bounded(output)
}

impl FileDiff {
    fn bounded(mut output: String) -> Self {
        if output.len() <= MAX_DIFF_BYTES {
            return Self {
                text: output,
                truncated: false,
            };
        }

        let total = output.len();
        let mut keep = MAX_DIFF_BYTES;
        while keep > 0 && !output.is_char_boundary(keep) {
            keep -= 1;
        }
        output.truncate(keep);
        output.push_str(&format!(
            "\n[diff truncated: kept {keep} of {total} bytes]\n"
        ));
        Self {
            text: output,
            truncated: true,
        }
    }
}

fn push_line(output: &mut String, prefix: char, line: &str) {
    output.push(prefix);
    output.push_str(line);
    if !line.ends_with('\n') {
        output.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_and_edit_diffs_are_deterministic_and_labeled() {
        let created = line_diff("", "alpha\nbeta\n", "notes.txt");
        assert!(!created.is_truncated());
        assert!(created.text().contains("--- a/notes.txt"));
        assert!(created.text().contains("+alpha\n"));
        assert!(created.text().contains("+beta\n"));

        let edited = line_diff("alpha\nbeta\ngamma\n", "alpha\nBETA\ngamma\n", "notes.txt");
        assert!(edited.text().contains("-beta\n"));
        assert!(edited.text().contains("+BETA\n"));
        assert_eq!(
            edited,
            line_diff("alpha\nbeta\ngamma\n", "alpha\nBETA\ngamma\n", "notes.txt")
        );
    }

    #[test]
    fn large_diffs_are_truncated_with_a_marker() {
        let old = "x\n".repeat(20_000);
        let new = "y\n".repeat(20_000);
        let diff = line_diff(&old, &new, "large.txt");
        assert!(diff.is_truncated());
        assert!(diff.text().contains("[diff truncated:"));
    }
}
