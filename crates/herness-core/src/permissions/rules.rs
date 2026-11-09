//! Structured permission rules and their matching semantics.
//!
//! A rule has an explicit [`RuleEffect`], a [`RuleTarget`], and a
//! [`MatchMethod`]. Matching is structural: file targets match normalized
//! absolute paths at a directory-component boundary, and shell targets match a
//! parsed simple command or the exact command string.
//!
//! # Shell rules are not a safety boundary
//!
//! A bash `allow` rule only means "this operation is not blocked by policy".
//! It is not an OS sandbox, not a proof that the command is harmless, and not a
//! promise about scripts or child processes the command starts. Simple program
//! prefixes are never treated as sufficient: a command such as `cargo test;
//! rm -rf .` is not the simple command `cargo test`, is rejected by the parser,
//! and can therefore only match an exact-command rule that spells it out.
//!
//! # Path matching
//!
//! File targets are normalized lexically (`.` and `..` are folded; component
//! boundaries are preserved). [`MatchMethod::ExactPath`] compares the whole
//! path. [`MatchMethod::PathPrefix`] matches the root itself and descendants of
//! the root, never a sibling whose name merely starts with the same characters.
//! Task 4 must still resolve the real path and reject symlink escapes before
//! touching the filesystem; lexical matching here is not an OS sandbox.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::Serialize;

use crate::contracts::errors::{ArgumentViolation, CoreError};
use crate::contracts::operation::FrozenOperation;
use crate::contracts::path::AbsolutePath;
use crate::tools::{ToolArguments, ToolName};

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// The operation may run when no deny or ask rule outranks it.
    Allow,
    /// The operation must not run, in either permission mode.
    Deny,
    /// The operation must wait for a human decider, in either permission mode.
    Ask,
}

impl fmt::Display for RuleEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
            Self::Ask => f.write_str("ask"),
        }
    }
}

/// How a rule target is compared with an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMethod {
    /// Matches every invocation of a tool.
    AnyInvocation,
    /// Matches one normalized absolute file path.
    ExactPath,
    /// Matches the root and descendants at a directory-component boundary.
    PathPrefix,
    /// Matches a parsed simple command whose program and arguments are exactly
    /// the configured ones.
    ExactArgv,
    /// Matches one trimmed command string byte-for-byte.
    ExactCommand,
}

impl MatchMethod {
    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnyInvocation => "any_invocation",
            Self::ExactPath => "exact_path",
            Self::PathPrefix => "path_prefix",
            Self::ExactArgv => "exact_argv",
            Self::ExactCommand => "exact_command",
        }
    }
}

impl fmt::Display for MatchMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a permission rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum RuleTarget {
    /// Every invocation of one tool.
    Tool {
        /// Tool the rule applies to.
        tool: ToolName,
    },
    /// A file path used by read, search, write, or edit.
    FilePath {
        /// File tool the rule applies to.
        tool: ToolName,
        /// Normalized absolute root path.
        root: AbsolutePath,
    },
    /// A parsed simple shell command by exact program and optional exact argv.
    ///
    /// `arguments` excludes the program. `None` means "any arguments for this
    /// program"; it is still only a policy match, not a command-safety claim.
    BashArgv {
        /// Exact program token.
        program: String,
        /// Exact argument tokens, or `None` for any arguments.
        arguments: Option<Vec<String>>,
    },
    /// One exact trimmed command string.
    BashCommand {
        /// Command string compared byte-for-byte after trimming.
        command: String,
    },
}

impl RuleTarget {
    /// Tool this target applies to.
    pub const fn tool(&self) -> ToolName {
        match self {
            Self::Tool { tool } | Self::FilePath { tool, .. } => *tool,
            Self::BashArgv { .. } | Self::BashCommand { .. } => ToolName::Bash,
        }
    }
}

/// A host-configured permission rule.
///
/// Rules are structural host configuration. They are not deserializable from
/// model or tool output: this type has no `Deserialize` implementation, and the
/// only mutation surface is [`crate::permissions::PolicyAdmin`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRule {
    effect: RuleEffect,
    target: RuleTarget,
    match_method: MatchMethod,
}

impl PermissionRule {
    /// Creates and validates a rule.
    ///
    /// The match method must fit the target: `AnyInvocation` for `Tool`,
    /// `ExactPath`/`PathPrefix` for `FilePath`, `ExactArgv` for `BashArgv`, and
    /// `ExactCommand` for `BashCommand`.
    pub fn new(
        effect: RuleEffect,
        target: RuleTarget,
        match_method: MatchMethod,
    ) -> Result<Self, CoreError> {
        let target = validate_target(target)?;
        let compatible = matches!(
            (&target, match_method),
            (RuleTarget::Tool { .. }, MatchMethod::AnyInvocation)
                | (
                    RuleTarget::FilePath { .. },
                    MatchMethod::ExactPath | MatchMethod::PathPrefix
                )
                | (RuleTarget::BashArgv { .. }, MatchMethod::ExactArgv)
                | (RuleTarget::BashCommand { .. }, MatchMethod::ExactCommand)
        );
        if !compatible {
            return Err(rule_error(format!(
                "match method {match_method} does not apply to target {}",
                target_kind(&target)
            )));
        }
        Ok(Self {
            effect,
            target,
            match_method,
        })
    }

    /// Creates an allow rule.
    pub fn allow(target: RuleTarget, match_method: MatchMethod) -> Result<Self, CoreError> {
        Self::new(RuleEffect::Allow, target, match_method)
    }

    /// Creates a deny rule.
    pub fn deny(target: RuleTarget, match_method: MatchMethod) -> Result<Self, CoreError> {
        Self::new(RuleEffect::Deny, target, match_method)
    }

    /// Creates an ask rule.
    pub fn ask(target: RuleTarget, match_method: MatchMethod) -> Result<Self, CoreError> {
        Self::new(RuleEffect::Ask, target, match_method)
    }

    /// Rule effect.
    pub const fn effect(&self) -> RuleEffect {
        self.effect
    }

    /// Rule target.
    pub const fn target(&self) -> &RuleTarget {
        &self.target
    }

    /// Comparison method.
    pub const fn match_method(&self) -> MatchMethod {
        self.match_method
    }

    /// Whether this rule matches the frozen operation.
    pub fn matches(&self, operation: &FrozenOperation) -> bool {
        match (&self.target, self.match_method) {
            (RuleTarget::Tool { tool }, MatchMethod::AnyInvocation) => operation.tool() == *tool,
            (RuleTarget::FilePath { tool, root }, MatchMethod::ExactPath) => {
                operation.tool() == *tool
                    && operation_file_path(operation)
                        .is_some_and(|path| path.as_path() == root.as_path())
            }
            (RuleTarget::FilePath { tool, root }, MatchMethod::PathPrefix) => {
                operation.tool() == *tool
                    && operation_file_path(operation)
                        .is_some_and(|path| path.as_path().starts_with(root.as_path()))
            }
            (RuleTarget::BashArgv { program, arguments }, MatchMethod::ExactArgv) => {
                operation_bash_command(operation)
                    .and_then(SimpleCommand::parse)
                    .is_some_and(|command| {
                        command.program == *program
                            && arguments
                                .as_ref()
                                .is_none_or(|expected| expected == &command.arguments)
                    })
            }
            (RuleTarget::BashCommand { command }, MatchMethod::ExactCommand) => {
                operation_bash_command(operation)
                    .is_some_and(|candidate| candidate.trim() == command)
            }
            _ => false,
        }
    }

    /// Whether this allow rule grants everything `other` allow rule grants.
    ///
    /// This is used when a child agent asks for a grant scope. Both rules must
    /// be allow rules. A parent tool-wide rule covers every target of that tool;
    /// a path prefix covers narrower paths; a bash program rule covers narrower
    /// argv; and an exact command covers only the identical command string.
    pub fn covers(&self, other: &Self) -> bool {
        if self.effect != RuleEffect::Allow || other.effect != RuleEffect::Allow {
            return false;
        }
        match (&self.target, &other.target) {
            (RuleTarget::Tool { tool: parent }, _) => other.target.tool() == *parent,
            (
                RuleTarget::FilePath {
                    tool: parent_tool,
                    root: parent_root,
                },
                RuleTarget::FilePath {
                    tool: child_tool,
                    root: child_root,
                },
            ) if parent_tool == child_tool => match (self.match_method, other.match_method) {
                (MatchMethod::ExactPath, MatchMethod::ExactPath) => parent_root == child_root,
                (MatchMethod::PathPrefix, MatchMethod::ExactPath | MatchMethod::PathPrefix) => {
                    child_root.as_path().starts_with(parent_root.as_path())
                }
                _ => false,
            },
            (
                RuleTarget::BashArgv {
                    program: parent_program,
                    arguments: parent_arguments,
                },
                RuleTarget::BashArgv {
                    program: child_program,
                    arguments: child_arguments,
                },
            ) if parent_program == child_program => match (parent_arguments, child_arguments) {
                (None, _) => true,
                (Some(parent), Some(child)) => parent == child,
                (Some(_), None) => false,
            },
            (
                RuleTarget::BashArgv {
                    program: parent_program,
                    arguments: parent_arguments,
                },
                RuleTarget::BashCommand { command },
            ) => SimpleCommand::parse(command).is_some_and(|parsed| {
                parsed.program == *parent_program
                    && parent_arguments
                        .as_ref()
                        .is_none_or(|expected| expected == &parsed.arguments)
            }),
            (
                RuleTarget::BashCommand {
                    command: parent_command,
                },
                RuleTarget::BashCommand {
                    command: child_command,
                },
            ) => parent_command == child_command,
            _ => false,
        }
    }
}

/// A parsed simple shell command.
///
/// The parser accepts words with single or double quotes. It rejects shell
/// operators, expansions, redirections, globs, and escapes so that a command
/// cannot be mistaken for a harmless simple command by a rule author. Rejected
/// commands can still be matched by [`MatchMethod::ExactCommand`] only when the
/// whole string is configured exactly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimpleCommand {
    program: String,
    arguments: Vec<String>,
}

impl SimpleCommand {
    /// Parses a simple command. Returns `None` for shell syntax that this
    /// parser does not model.
    pub fn parse(command: &str) -> Option<Self> {
        let mut tokens: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut has_token = false;
        let mut single_quoted = false;
        let mut double_quoted = false;

        for character in command.chars() {
            if matches!(character, '\n' | '\r' | '\0') {
                // Newlines separate commands. NUL is never a valid command
                // character and must not become part of a matched token.
                return None;
            }
            if single_quoted {
                if character == '\'' {
                    single_quoted = false;
                } else {
                    current.push(character);
                }
                has_token = true;
                continue;
            }
            if double_quoted {
                match character {
                    '"' => double_quoted = false,
                    '$' | '`' | '\\' => return None,
                    other => current.push(other),
                }
                has_token = true;
                continue;
            }
            match character {
                '\'' => {
                    single_quoted = true;
                    has_token = true;
                }
                '"' => {
                    double_quoted = true;
                    has_token = true;
                }
                ' ' | '\t' => {
                    if has_token {
                        tokens.push(std::mem::take(&mut current));
                        has_token = false;
                    }
                }
                '\\' | '$' | '`' | ';' | '|' | '&' | '<' | '>' | '(' | ')' | '{' | '}' | '*'
                | '?' | '[' | ']' | '~' | '#' | '!' => return None,
                other => {
                    current.push(other);
                    has_token = true;
                }
            }
        }

        if single_quoted || double_quoted {
            return None;
        }
        if has_token {
            tokens.push(current);
        }
        let mut tokens = tokens.into_iter();
        let program = tokens.next()?;
        if program.is_empty() || program.contains('=') {
            // An assignment prefix such as `FOO=bar cmd` is not a program.
            return None;
        }
        Some(Self {
            program,
            arguments: tokens.collect(),
        })
    }

    /// Program token.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Argument tokens, excluding the program.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

impl FromStr for SimpleCommand {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or(())
    }
}

/// Resolves an operation's file argument to a normalized absolute path.
///
/// Search without an explicit path scopes to the frozen working directory.
/// Bash and candidate artifact tools have no project file argument and return
/// `None`.
pub(crate) fn operation_file_path(operation: &FrozenOperation) -> Option<AbsolutePath> {
    let raw = match operation.arguments() {
        ToolArguments::Read(arguments) => arguments.path.as_str(),
        ToolArguments::Search(arguments) => arguments
            .path
            .as_ref()
            .map_or_else(|| operation.cwd().as_str(), |path| path.as_str()),
        ToolArguments::Write(arguments) => arguments.path.as_str(),
        ToolArguments::Edit(arguments) => arguments.path.as_str(),
        ToolArguments::Bash(_)
        | ToolArguments::CandidateRead(_)
        | ToolArguments::CandidateWrite(_)
        | ToolArguments::CandidateEdit(_) => return None,
    };
    resolve_path(operation.cwd(), raw)
}

/// Resolves a possibly relative path against the frozen cwd and normalizes it.
pub(crate) fn resolve_path(cwd: &AbsolutePath, raw: &str) -> Option<AbsolutePath> {
    let raw = Path::new(raw);
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.as_path().join(raw)
    };
    normalize_absolute(&joined)
}

/// Lexically normalizes an absolute path. This does not resolve symlinks.
pub(crate) fn normalize_absolute(path: &Path) -> Option<AbsolutePath> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    AbsolutePath::new(normalized.to_str()?).ok()
}

fn operation_bash_command(operation: &FrozenOperation) -> Option<&str> {
    match operation.arguments() {
        ToolArguments::Bash(arguments) => Some(arguments.command.as_str()),
        _ => None,
    }
}

fn validate_target(target: RuleTarget) -> Result<RuleTarget, CoreError> {
    match target {
        RuleTarget::Tool { .. } => Ok(target),
        RuleTarget::FilePath { tool, root } => {
            if !matches!(
                tool,
                ToolName::Read | ToolName::Search | ToolName::Write | ToolName::Edit
            ) {
                return Err(rule_error(
                    "file path rules apply to read, search, write, and edit only".to_owned(),
                ));
            }
            let normalized = normalize_absolute(root.as_path()).ok_or_else(|| {
                rule_error("file path root is not a valid absolute path".to_owned())
            })?;
            Ok(RuleTarget::FilePath {
                tool,
                root: normalized,
            })
        }
        RuleTarget::BashArgv { program, arguments } => {
            let program = program.trim();
            if program.is_empty() {
                return Err(rule_error("bash program must not be empty".to_owned()));
            }
            if program.contains('\0') || arguments.iter().flatten().any(|arg| arg.contains('\0')) {
                return Err(rule_error(
                    "bash rule must not contain a NUL byte".to_owned(),
                ));
            }
            Ok(RuleTarget::BashArgv {
                program: program.to_owned(),
                arguments,
            })
        }
        RuleTarget::BashCommand { command } => {
            let command = command.trim();
            if command.is_empty() {
                return Err(rule_error("bash command must not be empty".to_owned()));
            }
            if command.contains('\0') {
                return Err(rule_error(
                    "bash command must not contain a NUL byte".to_owned(),
                ));
            }
            Ok(RuleTarget::BashCommand {
                command: command.to_owned(),
            })
        }
    }
}

fn target_kind(target: &RuleTarget) -> &'static str {
    match target {
        RuleTarget::Tool { .. } => "tool",
        RuleTarget::FilePath { .. } => "file_path",
        RuleTarget::BashArgv { .. } => "bash_argv",
        RuleTarget::BashCommand { .. } => "bash_command",
    }
}

fn rule_error(detail: String) -> CoreError {
    CoreError::InvalidValue {
        field: "permissionRule".to_owned(),
        violation: ArgumentViolation::Invalid { detail },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::ids::{OperationId, ProjectId, RunId};
    use crate::contracts::operation::FrozenOperation;
    use crate::permissions::PermissionMode;
    use crate::permissions::PolicyVersion;
    use crate::tools::{NonEmptyText, ReadArgs, WriteArgs};

    fn operation(tool: ToolName, arguments: ToolArguments, cwd: &str) -> FrozenOperation {
        let project = ProjectId::new();
        FrozenOperation::new(
            OperationId::new(project),
            RunId::new(project),
            tool,
            arguments,
            AbsolutePath::new(cwd).expect("absolute cwd"),
            PolicyVersion::INITIAL,
            PermissionMode::Configured,
        )
        .expect("valid operation")
    }

    #[test]
    fn path_prefix_matches_components_not_substrings() {
        let rule = PermissionRule::allow(
            RuleTarget::FilePath {
                tool: ToolName::Write,
                root: AbsolutePath::new("/tmp/project").expect("absolute"),
            },
            MatchMethod::PathPrefix,
        )
        .expect("rule");

        let inside = operation(
            ToolName::Write,
            ToolArguments::Write(WriteArgs {
                path: NonEmptyText::new("src/main.rs").expect("path"),
                content: "x".to_owned(),
                rationale: crate::tools::Rationale::new("test").expect("rationale"),
            }),
            "/tmp/project",
        );
        let sibling = operation(
            ToolName::Write,
            ToolArguments::Write(WriteArgs {
                path: NonEmptyText::new("/tmp/projection/file").expect("path"),
                content: "x".to_owned(),
                rationale: crate::tools::Rationale::new("test").expect("rationale"),
            }),
            "/tmp/project",
        );
        let escaped = operation(
            ToolName::Write,
            ToolArguments::Write(WriteArgs {
                path: NonEmptyText::new("../projection/file").expect("path"),
                content: "x".to_owned(),
                rationale: crate::tools::Rationale::new("test").expect("rationale"),
            }),
            "/tmp/project",
        );

        assert!(rule.matches(&inside));
        assert!(!rule.matches(&sibling));
        assert!(!rule.matches(&escaped));
    }

    #[test]
    fn exact_path_and_search_cwd_matching() {
        let rule = PermissionRule::allow(
            RuleTarget::FilePath {
                tool: ToolName::Search,
                root: AbsolutePath::new("/tmp/project").expect("absolute"),
            },
            MatchMethod::PathPrefix,
        )
        .expect("rule");
        let search = operation(
            ToolName::Search,
            ToolArguments::Search(crate::tools::SearchArgs {
                query: NonEmptyText::new("needle").expect("query"),
                path: None,
                glob: None,
                max_results: None,
            }),
            "/tmp/project",
        );
        assert!(rule.matches(&search));
    }

    #[test]
    fn simple_command_parser_rejects_shell_syntax() {
        let command = SimpleCommand::parse("cargo test --release").expect("simple command");
        assert_eq!(command.program(), "cargo");
        assert_eq!(command.arguments(), ["test", "--release"]);
        assert_eq!(
            SimpleCommand::parse("echo 'a b'")
                .expect("quoted")
                .arguments(),
            ["a b"]
        );
        assert!(SimpleCommand::parse("cargo test; rm -rf .").is_none());
        assert!(SimpleCommand::parse("cargo test | tee out").is_none());
        assert!(SimpleCommand::parse("cargo\ntest").is_none());
        assert!(SimpleCommand::parse("cargo test && curl example.invalid").is_none());
        assert!(SimpleCommand::parse("FOO=bar cargo test").is_none());
        assert!(SimpleCommand::parse("echo $HOME").is_none());
        assert!(SimpleCommand::parse("echo `id`").is_none());
        assert!(SimpleCommand::parse("echo *.rs").is_none());
        assert!(SimpleCommand::parse("echo 'unterminated").is_none());
    }

    #[test]
    fn rule_validation_rejects_mismatched_match_methods() {
        assert!(
            PermissionRule::allow(
                RuleTarget::Tool {
                    tool: ToolName::Read
                },
                MatchMethod::ExactPath
            )
            .is_err()
        );
        assert!(
            PermissionRule::allow(
                RuleTarget::BashArgv {
                    program: "cargo".to_owned(),
                    arguments: None
                },
                MatchMethod::ExactCommand
            )
            .is_err()
        );
        assert!(
            PermissionRule::allow(
                RuleTarget::FilePath {
                    tool: ToolName::Bash,
                    root: AbsolutePath::new("/tmp").expect("absolute")
                },
                MatchMethod::PathPrefix
            )
            .is_err()
        );
    }

    #[test]
    fn read_path_is_not_a_write_grant() {
        let read_rule = PermissionRule::allow(
            RuleTarget::FilePath {
                tool: ToolName::Read,
                root: AbsolutePath::new("/tmp/project").expect("absolute"),
            },
            MatchMethod::PathPrefix,
        )
        .expect("rule");
        let read = operation(
            ToolName::Read,
            ToolArguments::Read(ReadArgs {
                path: NonEmptyText::new("notes.txt").expect("path"),
                offset: None,
                limit: None,
            }),
            "/tmp/project",
        );
        let write = operation(
            ToolName::Write,
            ToolArguments::Write(WriteArgs {
                path: NonEmptyText::new("notes.txt").expect("path"),
                content: "x".to_owned(),
                rationale: crate::tools::Rationale::new("test").expect("rationale"),
            }),
            "/tmp/project",
        );
        assert!(read_rule.matches(&read));
        assert!(!read_rule.matches(&write));
    }
}
