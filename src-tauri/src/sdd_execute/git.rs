//! Fixed-argv Git access for the desktop H4 workspace adapter.
//!
//! Every Git call is one fixed argv in the selected checkout, launched through
//! the shared [`ProcessSupervisor`] under
//! [`ManagedOwner::HostActivity`]. No `sh -c` string, no `PATH` lookup, no
//! editor, pager, or credential prompt can start, and no output is interpreted
//! as a shell command.
//!
//! The read helpers pass `--no-optional-locks` (and the child environment
//! carries `GIT_OPTIONAL_LOCKS=0`), so `git status` never refreshes — and
//! therefore never rewrites — the index. The only mutating helpers are the
//! three used by explicit isolation and its own failed-creation cleanup:
//! `worktree add --detach`, `switch -c`, and `worktree remove`. Stage, gate, and
//! commit are deliberately absent: both the one permitted preparation commit and
//! every Task commit run through `herness_core`'s host Git boundary, never
//! through this module. The change and read helpers here are read-only queries
//! the commit half uses to fix and re-read the target set.

use std::time::Duration;

use herness_core::contracts::{HostActivityId, ProjectId};
use herness_core::tools::process::{
    ArgvLauncher, ArgvRequest, CaptureHandle, DEFAULT_CAPTURE_TIMEOUT, DEFAULT_CONFIRM_TIMEOUT,
    DEFAULT_OUTPUT_LIMIT, DEFAULT_TIMEOUT_GRACE, ManagedChild, ManagedOwner, ProcessSupervisor,
    SystemArgvLauncher, supervise,
};
use herness_core::{AbsolutePath, ShellStopStatus};
use herness_sdd_execute::{CommitSha, FailureDetails, RecoveryReason, SddExecutionError, TreeSha};
use sha2::Digest as _;
use uuid::Uuid;

/// Hard ceiling for one workspace Git process group.
///
/// The H4 host commit budget is separate; workspace observation and the one
/// explicit isolation step only create a worktree, never commit content.
pub const WORKSPACE_GIT_TIMEOUT: Duration = Duration::from_secs(30);

const GIT_ENVIRONMENT: &[(&str, &str)] = &[
    // Never wait for interactive credentials; there is no network command.
    ("GIT_TERMINAL_PROMPT", "0"),
    // Stable, parseable output.
    ("LC_ALL", "C"),
    // No editor or pager can start inside a managed group.
    ("GIT_PAGER", "cat"),
    ("PAGER", "cat"),
    ("GIT_EDITOR", "true"),
    // Belt and braces with `--no-optional-locks`: an observation must not
    // refresh the index.
    ("GIT_OPTIONAL_LOCKS", "0"),
];

/// One finished Git process group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitProcessOutput {
    status: ShellStopStatus,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl GitProcessOutput {
    /// Whether the process exited with code 0.
    pub fn succeeded(&self) -> bool {
        self.status == ShellStopStatus::Completed && self.exit_code == Some(0)
    }

    /// Observed stop status.
    pub const fn status(&self) -> ShellStopStatus {
        self.status
    }

    /// Exit code, when the process exited normally.
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Captured stdout.
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    /// Captured stderr.
    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    /// Bounded single-line description of the failure.
    pub fn detail(&self) -> String {
        let source = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        let mut text = String::new();
        for character in source.chars() {
            if character.is_control() {
                if character == '\n' || character == '\t' {
                    text.push(' ');
                }
                continue;
            }
            text.push(character);
            if text.len() >= 300 {
                break;
            }
        }
        let trimmed = text.trim();
        if trimmed.is_empty() {
            format!("git exited with {:?}", self.exit_code)
        } else {
            trimmed.to_owned()
        }
    }
}

/// One `git status --porcelain` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStatusEntry {
    index: char,
    worktree: char,
    path: String,
}

impl GitStatusEntry {
    /// Index (`X`) column.
    pub const fn index(&self) -> char {
        self.index
    }

    /// Worktree (`Y`) column.
    pub const fn worktree(&self) -> char {
        self.worktree
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// One changed path observed against a base revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitChange {
    path: String,
    kind: GitChangeKind,
}

impl GitChange {
    /// Records one changed path and what happened to it.
    pub fn new(path: impl Into<String>, kind: GitChangeKind) -> Self {
        Self {
            path: path.into(),
            kind,
        }
    }

    /// Project-relative path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What changed.
    pub const fn kind(&self) -> GitChangeKind {
        self.kind
    }
}

/// What happened to one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitChangeKind {
    /// The path is new.
    Added,
    /// The path exists at both revisions with different bytes.
    Modified,
    /// The path exists at the base and not in the worktree.
    Deleted,
}

/// Parsed `git status --porcelain` state of one checkout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitWorktreeStatus {
    entries: Vec<GitStatusEntry>,
}

impl GitWorktreeStatus {
    /// Whether the index holds no staged change.
    ///
    /// An untracked entry is not a staged change.
    pub fn index_clean(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| entry.index == ' ' || entry.index == '?')
    }

    /// Whether the worktree holds no modification, deletion, or untracked file.
    pub fn worktree_clean(&self) -> bool {
        self.entries.iter().all(|entry| entry.worktree == ' ')
    }

    /// Whether both the index and the worktree are clean.
    pub fn is_clean(&self) -> bool {
        self.index_clean() && self.worktree_clean()
    }

    /// Every reported entry.
    pub fn entries(&self) -> &[GitStatusEntry] {
        &self.entries
    }

    /// Reported paths.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.path.as_str())
    }
}

/// One `git worktree list --porcelain` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitWorktree {
    path: String,
    head: Option<String>,
    branch: Option<String>,
    detached: bool,
}

impl GitWorktree {
    /// Absolute worktree path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// HEAD object name, when Git reported one.
    pub fn head(&self) -> Option<&str> {
        self.head.as_deref()
    }

    /// Short branch name, when the worktree is on a branch.
    pub fn branch(&self) -> Option<&str> {
        self.branch.as_deref()
    }

    /// Whether the worktree has a detached HEAD.
    pub const fn is_detached(&self) -> bool {
        self.detached
    }
}

/// Read-only and explicit-isolation Git access for one project.
pub struct GitRunner<L = SystemArgvLauncher> {
    program: AbsolutePath,
    launcher: L,
    supervisor: ProcessSupervisor,
    activity: HostActivityId,
    timeout: Duration,
    output_limit: usize,
}

impl<L> GitRunner<L> {
    /// Creates a runner for one project.
    pub fn new(
        program: AbsolutePath,
        launcher: L,
        supervisor: ProcessSupervisor,
        project_id: ProjectId,
    ) -> Result<Self, SddExecutionError> {
        if !program.as_path().is_absolute() {
            return Err(invalid(
                "gitProgram",
                "must be an absolute path to the Git executable",
            ));
        }
        Ok(Self {
            program,
            launcher,
            supervisor,
            activity: workspace_activity(project_id),
            timeout: WORKSPACE_GIT_TIMEOUT,
            output_limit: DEFAULT_OUTPUT_LIMIT,
        })
    }

    /// Replaces the per-process timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces the per-stream capture retention.
    #[must_use]
    pub const fn with_output_limit(mut self, limit: usize) -> Self {
        self.output_limit = limit;
        self
    }

    /// Absolute Git program path.
    pub const fn program(&self) -> &AbsolutePath {
        &self.program
    }

    /// Host activity that owns every Git group of this runner.
    pub const fn activity_id(&self) -> HostActivityId {
        self.activity
    }
}

impl<L: ArgvLauncher> GitRunner<L> {
    /// Reads the checkout identity of `cwd`, if it is a Git working tree.
    pub fn repository_root(&mut self, cwd: &str) -> Result<Option<String>, SddExecutionError> {
        let output = self.run(cwd, &["rev-parse", "--show-toplevel"], true)?;
        if !output.succeeded() {
            return Ok(None);
        }
        let root = output.stdout().trim();
        Ok((!root.is_empty()).then(|| root.to_owned()))
    }

    /// Reads the absolute common Git directory of `cwd`.
    ///
    /// Two checkouts belong to one repository exactly when this value is equal,
    /// so a linked worktree of the original checkout is indistinguishable from it
    /// for ownership purposes.
    pub fn common_git_dir(&mut self, cwd: &str) -> Result<Option<String>, SddExecutionError> {
        let output = self.run(cwd, &["rev-parse", "--git-common-dir"], true)?;
        if !output.succeeded() {
            return Ok(None);
        }
        let value = output.stdout().trim();
        if value.is_empty() {
            return Ok(None);
        }
        let path = std::path::Path::new(value);
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::path::Path::new(cwd).join(path)
        };
        let canonical = std::fs::canonicalize(&absolute).unwrap_or(absolute);
        Ok(Some(canonical.to_string_lossy().into_owned()))
    }

    /// Reads HEAD as a full commit SHA.
    pub fn head(&mut self, cwd: &str) -> Result<Option<CommitSha>, SddExecutionError> {
        self.rev_parse_commit(cwd, "HEAD")
    }

    /// Resolves one revision to a full commit SHA, or `None` when it does not
    /// exist.
    pub fn rev_parse_commit(
        &mut self,
        cwd: &str,
        revision: &str,
    ) -> Result<Option<CommitSha>, SddExecutionError> {
        let specification = format!("{revision}^{{commit}}");
        let output = self.run(
            cwd,
            &["rev-parse", "--verify", "--quiet", &specification],
            true,
        )?;
        if !output.succeeded() {
            return Ok(None);
        }
        let value = output.stdout().trim();
        if value.is_empty() {
            return Ok(None);
        }
        CommitSha::parse(value).map(Some)
    }

    /// Reads the current branch, or `None` for a detached HEAD.
    pub fn current_branch(&mut self, cwd: &str) -> Result<Option<String>, SddExecutionError> {
        let output = self.run(cwd, &["branch", "--show-current"], true)?;
        if !output.succeeded() {
            return Ok(None);
        }
        let branch = output.stdout().trim();
        Ok((!branch.is_empty()).then(|| branch.to_owned()))
    }

    /// Reads one revision to a full tree SHA, or `None` when it does not exist.
    pub fn rev_parse_tree(
        &mut self,
        cwd: &str,
        revision: &str,
    ) -> Result<Option<TreeSha>, SddExecutionError> {
        let specification = format!("{revision}^{{tree}}");
        let output = self.run(
            cwd,
            &["rev-parse", "--verify", "--quiet", &specification],
            true,
        )?;
        if !output.succeeded() {
            return Ok(None);
        }
        let value = output.stdout().trim();
        if value.is_empty() {
            return Ok(None);
        }
        TreeSha::parse(value).map(Some)
    }

    /// Reads the full commit message of `HEAD`, without the trailing newline.
    pub fn commit_message(&mut self, cwd: &str) -> Result<String, SddExecutionError> {
        let output = self.run(cwd, &["log", "-1", "--pretty=%B", "HEAD"], true)?;
        if !output.succeeded() {
            return Err(unavailable("workspace.git", output.detail()));
        }
        Ok(output.stdout().trim_end().to_owned())
    }

    /// Lists the paths whose index entry differs from HEAD.
    pub fn staged_paths(&mut self, cwd: &str) -> Result<Vec<String>, SddExecutionError> {
        let output = self.run(
            cwd,
            &[
                "diff",
                "--cached",
                "--name-only",
                "--no-renames",
                "-z",
                "HEAD",
            ],
            true,
        )?;
        // An unborn branch has no HEAD to diff against; nothing is staged.
        if output.exit_code() == Some(128) {
            return Ok(Vec::new());
        }
        if !output.succeeded() {
            return Err(unavailable("workspace.git", output.detail()));
        }
        Ok(output
            .stdout()
            .split('\0')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// Lists every path that differs from `base`, including deletions.
    ///
    /// The result is the worktree/index state against `base`, so it covers both
    /// committed and still-uncommitted work. It never refreshes the index.
    pub fn changes_since(
        &mut self,
        cwd: &str,
        base: &str,
    ) -> Result<Vec<GitChange>, SddExecutionError> {
        let output = self.run(
            cwd,
            &["diff", "--name-status", "--no-renames", "-z", base],
            true,
        )?;
        if !output.succeeded() {
            return Err(unavailable("workspace.git", output.detail()));
        }
        let mut changes = Vec::new();
        let mut fields = output
            .stdout()
            .split('\0')
            .filter(|value| !value.is_empty());
        while let Some(status) = fields.next() {
            let Some(path) = fields.next() else {
                return Err(unavailable(
                    "workspace.git",
                    "git diff returned a status without a path".to_owned(),
                ));
            };
            let kind = match status.trim() {
                "D" => GitChangeKind::Deleted,
                "A" => GitChangeKind::Added,
                _ => GitChangeKind::Modified,
            };
            changes.push(GitChange {
                path: path.to_owned(),
                kind,
            });
        }
        Ok(changes)
    }

    /// Lists the untracked, non-ignored paths.
    ///
    /// `--untracked-files=all` expands a wholly untracked directory into its
    /// files, so a new document inside a new directory is one explicit target
    /// rather than a directory entry the host would have to expand itself.
    pub fn untracked_paths(&mut self, cwd: &str) -> Result<Vec<String>, SddExecutionError> {
        let output = self.run(
            cwd,
            &[
                "status",
                "--porcelain",
                "-z",
                "--no-renames",
                "--untracked-files=all",
            ],
            true,
        )?;
        if !output.succeeded() {
            return Err(unavailable("workspace.git", output.detail()));
        }
        let mut paths = Vec::new();
        for record in output
            .stdout()
            .split('\0')
            .filter(|value| !value.is_empty())
        {
            let mut characters = record.chars();
            let Some(index) = characters.next() else {
                continue;
            };
            let Some(worktree) = characters.next() else {
                continue;
            };
            if index != '?' || worktree != '?' {
                continue;
            }
            let rest: String = characters.collect();
            let path = rest.strip_prefix(' ').unwrap_or(&rest);
            if !path.is_empty() {
                paths.push(path.to_owned());
            }
        }
        Ok(paths)
    }

    /// Whether Git would ignore `path`.
    ///
    /// `--no-index` asks the ignore rules rather than about one tracked file, so
    /// a path that does not exist in the index is still classified.
    pub fn is_ignored(&mut self, cwd: &str, path: &str) -> Result<bool, SddExecutionError> {
        let output = self.run(cwd, &["check-ignore", "--no-index", "--quiet", path], true)?;
        match output.exit_code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(unavailable("workspace.git", output.detail())),
        }
    }

    /// Reads the index and worktree state without refreshing the index.
    pub fn status(&mut self, cwd: &str) -> Result<GitWorktreeStatus, SddExecutionError> {
        let output = self.run(
            cwd,
            &[
                "status",
                "--porcelain",
                "-z",
                "--no-renames",
                "--untracked-files=normal",
            ],
            true,
        )?;
        if !output.succeeded() {
            return Err(unavailable("workspace.git", output.detail()));
        }
        let mut entries = Vec::new();
        for record in output
            .stdout()
            .split('\0')
            .filter(|value| !value.is_empty())
        {
            let mut characters = record.chars();
            let Some(index) = characters.next() else {
                continue;
            };
            let Some(worktree) = characters.next() else {
                continue;
            };
            // The porcelain v1 record is `XY <path>`; `--no-renames` keeps one
            // record per path.
            let rest: String = characters.collect();
            let path = rest.strip_prefix(' ').unwrap_or(&rest);
            if path.is_empty() {
                continue;
            }
            entries.push(GitStatusEntry {
                index,
                worktree,
                path: path.to_owned(),
            });
        }
        Ok(GitWorktreeStatus { entries })
    }

    /// Lists every worktree of the repository that contains `cwd`.
    pub fn worktrees(&mut self, cwd: &str) -> Result<Vec<GitWorktree>, SddExecutionError> {
        let output = self.run(cwd, &["worktree", "list", "--porcelain"], true)?;
        if !output.succeeded() {
            return Err(unavailable("workspace.git", output.detail()));
        }
        let mut worktrees = Vec::new();
        let mut path: Option<String> = None;
        let mut head: Option<String> = None;
        let mut branch: Option<String> = None;
        let mut detached = false;
        for line in output.stdout().lines() {
            if line.is_empty() {
                if let Some(current) = path.take() {
                    worktrees.push(GitWorktree {
                        path: current,
                        head: head.take(),
                        branch: branch.take(),
                        detached,
                    });
                    detached = false;
                }
                continue;
            }
            if let Some(value) = line.strip_prefix("worktree ") {
                path = Some(value.trim().to_owned());
            } else if let Some(value) = line.strip_prefix("HEAD ") {
                head = Some(value.trim().to_owned());
            } else if let Some(value) = line.strip_prefix("branch ") {
                branch = Some(
                    value
                        .trim()
                        .strip_prefix("refs/heads/")
                        .unwrap_or(value.trim())
                        .to_owned(),
                );
            } else if line.trim() == "detached" {
                detached = true;
            }
        }
        if let Some(current) = path.take() {
            worktrees.push(GitWorktree {
                path: current,
                head,
                branch,
                detached,
            });
        }
        Ok(worktrees)
    }

    /// Adds a detached worktree at `target` from `base`.
    ///
    /// No branch is created here. A failure therefore cannot leave a new branch
    /// behind, which is why the adapter never calls `worktree add -b`.
    pub(crate) fn add_detached_worktree(
        &mut self,
        repository: &str,
        target: &str,
        base: &str,
    ) -> Result<GitProcessOutput, SddExecutionError> {
        self.run(
            repository,
            &["worktree", "add", "--detach", target, base],
            false,
        )
    }

    /// Creates `branch` at the current HEAD inside `worktree`.
    pub(crate) fn create_branch_in_worktree(
        &mut self,
        worktree: &str,
        branch: &str,
    ) -> Result<GitProcessOutput, SddExecutionError> {
        self.run(worktree, &["switch", "--create", branch], false)
    }

    /// Removes a worktree created by this adapter in the same preparation.
    pub(crate) fn remove_worktree(
        &mut self,
        repository: &str,
        target: &str,
    ) -> Result<GitProcessOutput, SddExecutionError> {
        self.run(repository, &["worktree", "remove", target], false)
    }

    fn run(
        &mut self,
        cwd: &str,
        args: &[&str],
        read_only: bool,
    ) -> Result<GitProcessOutput, SddExecutionError> {
        let cwd = AbsolutePath::new(cwd).map_err(|error| invalid("cwd", &error.to_string()))?;
        let mut argv: Vec<String> = Vec::with_capacity(args.len() + 1);
        if read_only {
            argv.push("--no-optional-locks".to_owned());
        }
        argv.extend(args.iter().map(|value| (*value).to_owned()));

        let request = ArgvRequest::new(self.program.as_str(), argv, cwd)
            .map_err(|error| unavailable("workspace.git", error.to_string()))?;
        let mut request = request;
        for (key, value) in GIT_ENVIRONMENT {
            request = request
                .with_env(*key, *value)
                .map_err(|error| unavailable("workspace.git", error.to_string()))?;
        }

        let Some(gate) = self.supervisor.begin_spawn() else {
            return Err(herness_sdd_execute::SddExecutionError::RecoveryRequired {
                reason: RecoveryReason::StopUnconfirmed,
                details: FailureDetails::none().boxed(),
            });
        };
        let mut child = match self.launcher.spawn_argv(&request) {
            Ok(child) => child,
            Err(error) => {
                drop(gate);
                return Err(unavailable("workspace.git", error.to_string()));
            }
        };
        let pid = child.pid();
        let pgid = pid;
        let lease = self
            .supervisor
            .register(ManagedOwner::HostActivity(self.activity), pid, pgid);
        drop(gate);
        let _lease = lease;

        let stdout = CaptureHandle::start(child.take_stdout(), self.output_limit);
        let stderr = CaptureHandle::start(child.take_stderr(), self.output_limit);
        let completion = supervise(
            &mut child,
            pgid,
            &self.supervisor,
            Some(self.timeout),
            DEFAULT_TIMEOUT_GRACE,
            DEFAULT_CONFIRM_TIMEOUT,
        );
        let stdout = stdout.wait(DEFAULT_CAPTURE_TIMEOUT);
        let stderr = stderr.wait(DEFAULT_CAPTURE_TIMEOUT);

        let output = GitProcessOutput {
            status: completion.stop_status(),
            exit_code: completion.exit_code(),
            stdout: stdout.text().to_owned(),
            stderr: stderr.text().to_owned(),
        };
        match completion.stop_status() {
            ShellStopStatus::Completed
            | ShellStopStatus::ExitedNonZero
            | ShellStopStatus::Killed
                if completion.confirmed() =>
            {
                Ok(output)
            }
            _ => Err(herness_sdd_execute::SddExecutionError::RecoveryRequired {
                reason: RecoveryReason::GitResultUnconfirmed,
                details: FailureDetails::none().boxed(),
            }),
        }
    }
}

/// Deterministic host-activity identity for this project's workspace reads.
fn workspace_activity(project_id: ProjectId) -> HostActivityId {
    let digest = sha2::Sha256::digest(format!("herness.h4.workspace\0{project_id}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    HostActivityId::from_parts(project_id, Uuid::from_bytes(bytes))
}

fn invalid(field: &str, detail: &str) -> SddExecutionError {
    SddExecutionError::InvalidValue {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}

fn unavailable(feature: &str, detail: String) -> SddExecutionError {
    SddExecutionError::Unavailable {
        feature: format!("{feature}: {detail}"),
        details: FailureDetails::none().boxed(),
    }
}
