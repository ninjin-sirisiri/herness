//! Desktop test-launch mode for real WKWebView render evidence.
//!
//! `--h3-render-test <fixture-dir> <output-dir>` is a test launcher, not a
//! production IPC surface. It runs in a desktop child process, reads the
//! hand-authored fixture from disk once, renders it through the same native
//! bridge later phases use, and writes the versioned manifest plus PNGs.
//!
//! The fixture reader is intentionally narrow: only the files named in
//! `fixture.json` are read, every path is canonicalised and kept under the
//! fixture root, and the render job itself only ever serves from memory.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use tauri::AppHandle;

use super::render::{CancellationToken, RenderBudget, RenderJob, RenderResource, render_candidate};

/// Parsed `--h3-render-test` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderTestLaunch {
    /// Directory containing `fixture.json`, HTML, CSS, and declared resources.
    pub fixture_dir: PathBuf,
    /// Evidence output directory.
    pub output_dir: PathBuf,
    /// Requested per-candidate timeout in milliseconds.
    pub budget_ms: u64,
    /// Optional test-only cancellation delay in milliseconds.
    pub cancel_after_ms: Option<u64>,
}

impl RenderTestLaunch {
    /// Creates a launch request with the default 30-second budget.
    pub fn new(fixture_dir: PathBuf, output_dir: PathBuf) -> Self {
        Self {
            fixture_dir,
            output_dir,
            budget_ms: 30_000,
            cancel_after_ms: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureSpec {
    html: String,
    css: String,
    resources: Vec<FixtureResource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FixtureResource {
    path: String,
    content_type: String,
}

/// Runs one fixture render and writes all evidence.
pub fn execute(app: &AppHandle, launch: &RenderTestLaunch) -> Result<(), String> {
    let job = load_fixture(&launch.fixture_dir)?;
    let budget = RenderBudget::new(Duration::from_millis(launch.budget_ms), None)
        .map_err(|error| error.to_string())?;
    let cancellation = CancellationToken::new();
    if let Some(delay) = launch.cancel_after_ms {
        let token = cancellation.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(delay));
            token.cancel("test cancellation");
        });
    }

    match render_candidate(app, &job, budget, &cancellation) {
        Ok(evidence) => {
            evidence
                .write_to(&launch.output_dir)
                .map_err(|error| format!("write render evidence: {error}"))?;
            println!(
                "H3_RENDER_OK job={} manifest={} configurations={} pngs={}",
                job.job_id(),
                launch.output_dir.join("manifest.json").display(),
                evidence.manifest().configurations.len(),
                evidence.pngs().len()
            );
            Ok(())
        }
        Err(failure) => {
            let label = failure.error().label();
            failure
                .write_to(&launch.output_dir)
                .map_err(|error| format!("write incomplete render evidence: {error}"))?;
            println!(
                "H3_RENDER_INCOMPLETE job={} reason={} manifest={}",
                job.job_id(),
                label,
                launch.output_dir.join("manifest.json").display()
            );
            Err(label)
        }
    }
}

fn load_fixture(directory: &Path) -> Result<RenderJob, String> {
    let root = std::fs::canonicalize(directory)
        .map_err(|error| format!("canonicalise fixture directory: {error}"))?;
    let spec_bytes = std::fs::read(root.join("fixture.json"))
        .map_err(|error| format!("read fixture.json: {error}"))?;
    let spec: FixtureSpec = serde_json::from_slice(&spec_bytes)
        .map_err(|error| format!("parse fixture.json: {error}"))?;
    if spec.resources.len() > 64 {
        return Err("fixture declares too many resources".to_owned());
    }
    let html = read_fixture_file(&root, &spec.html)?;
    let css = read_fixture_file(&root, &spec.css)?;
    let mut resources = Vec::with_capacity(spec.resources.len());
    for resource in spec.resources {
        validate_relative(&resource.path)?;
        if !resource.content_type.starts_with("image/")
            && resource.content_type != "font/woff2"
            && resource.content_type != "font/woff"
        {
            return Err(format!(
                "fixture resource `{}` has an unsupported content type",
                resource.path
            ));
        }
        let bytes = read_fixture_file(&root, &resource.path)?;
        resources.push(
            RenderResource::new(resource.path, resource.content_type, bytes)
                .map_err(|error| error.to_string())?,
        );
    }
    let job_id = uuid::Uuid::new_v4().simple().to_string();
    RenderJob::new(job_id, html, css, resources).map_err(|error| error.to_string())
}

fn read_fixture_file(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    validate_relative(relative)?;
    let candidate = root.join(relative);
    let canonical = std::fs::canonicalize(&candidate)
        .map_err(|error| format!("resolve fixture file `{relative}`: {error}"))?;
    if !canonical.starts_with(root) {
        return Err(format!(
            "fixture file `{relative}` escapes the fixture root"
        ));
    }
    let metadata = std::fs::metadata(&canonical)
        .map_err(|error| format!("stat fixture file `{relative}`: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("fixture path `{relative}` is not a regular file"));
    }
    std::fs::read(&canonical).map_err(|error| format!("read fixture file `{relative}`: {error}"))
}

fn validate_relative(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 512
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains('%')
        || path.contains('?')
        || path.contains('#')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(format!("fixture path `{path}` is not a safe relative path"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_paths_reject_escapes_and_absolute_names() {
        for path in [
            "../secret.txt",
            "/etc/passwd",
            "a/../../b",
            "a//b",
            "a\\b",
            "%2e%2e",
        ] {
            assert!(validate_relative(path).is_err(), "{path} must be rejected");
        }
        assert!(validate_relative("assets/diagram.svg").is_ok());
        assert!(validate_relative("candidate.html").is_ok());
    }

    #[test]
    fn the_default_launch_uses_the_hard_candidate_timeout() {
        let launch = RenderTestLaunch::new(PathBuf::from("fixture"), PathBuf::from("out"));
        assert_eq!(launch.budget_ms, 30_000);
        assert_eq!(launch.cancel_after_ms, None);
    }
}
