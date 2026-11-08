//! Shared fixtures for black-box herness runtime contract tests.
//!
//! Fixtures create synthetic projects and identifiers only. They never read
//! real credentials, Keychain entries, or external services.

pub mod fixtures;

#[cfg(test)]
mod tests {
    use super::fixtures::ProjectFixture;

    #[test]
    fn fixture_ids_share_one_project() {
        let fixture = ProjectFixture::new();
        assert_eq!(fixture.agent_id.project_id(), fixture.project_id);
        assert_eq!(fixture.session_id.project_id(), fixture.project_id);
        assert_eq!(fixture.run_id.project_id(), fixture.project_id);
        assert_eq!(fixture.operation_id().project_id(), fixture.project_id);
    }
}
