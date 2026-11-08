//! Phase A acceptance fixture for the opt-in real-connection boundary.
//!
//! This test file never contacts a provider, reads the Keychain, or launches
//! the desktop binary. It locks in the rule that real checks are explicit,
//! single-connection controller invocations and that normal window automation
//! (`--smoke-test`, `--close-reopen-test`, `--quit-test`) never selects one.

use herness_core::ConnectionId;
use herness_desktop::real_check::{CliAction, RealCheckArgs, RealCheckMode, parse_cli};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn normal_window_automation_never_selects_a_real_check() {
    for automation in [
        "--smoke-test",
        "--close-reopen-test",
        "--quit-test",
        "--some-future-flag",
    ] {
        assert_eq!(
            parse_cli(args(&[automation])).expect("normal flags parse"),
            None,
            "{automation} must not trigger a real provider check"
        );
    }
}

#[test]
fn every_real_check_mode_needs_an_explicit_stored_connection() {
    let connection = ConnectionId::new();
    let connection_id = connection.to_string();
    let cases = [
        (Vec::<&str>::new(), RealCheckMode::Request),
        (vec!["--list-models"], RealCheckMode::ListModels),
        (vec!["--refresh"], RealCheckMode::Refresh),
        (vec!["--sign-out"], RealCheckMode::SignOut),
    ];
    for (flags, mode) in cases {
        let mut values = vec!["--real-check".to_owned(), connection_id.clone()];
        values.extend(flags.iter().map(|flag| (*flag).to_owned()));
        assert_eq!(
            parse_cli(values).expect("explicit real check"),
            Some(CliAction::RealCheck(RealCheckArgs { connection, mode }))
        );
    }
}

#[test]
fn a_forget_request_is_separate_from_a_provider_check() {
    let connection = ConnectionId::new();
    let connection_id = connection.to_string();
    assert_eq!(
        parse_cli(vec![
            "--forget-connection".to_owned(),
            connection_id.clone()
        ])
        .expect("forget parses"),
        Some(CliAction::Forget(connection))
    );
    assert!(
        parse_cli(vec![
            "--real-check".to_owned(),
            connection_id.clone(),
            "--forget-connection".to_owned(),
            connection_id,
        ])
        .is_err()
    );
}

#[test]
fn missing_or_ambiguous_mode_flags_are_rejected() {
    assert!(parse_cli(args(&["--real-check"])).is_err());
    assert!(parse_cli(args(&["--real-check", "not-a-connection"])).is_err());
    assert!(parse_cli(args(&["--refresh"])).is_err());
    let connection_id = ConnectionId::new().to_string();
    assert!(
        parse_cli(vec![
            "--real-check".to_owned(),
            connection_id,
            "--refresh".to_owned(),
            "--sign-out".to_owned(),
        ])
        .is_err()
    );
}
