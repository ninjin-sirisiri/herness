//! Durable engine event queue and SDK event translation.
//!
//! The pi-embedded session saves its snapshot before it publishes a session
//! event. The listener in this module runs only after that save returned, so
//! every [`EngineEvent`] derived from an SDK event corresponds to host state
//! that is already durable. The queue itself is not a store: it is a transport
//! from the adapter to the host runtime.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use herness_core::{EngineEvent, EngineFailureKind, RunState, ToolArguments, ToolName};
use pi_agent::AgentEvent;
use pi_ai::{AssistantMessageEvent, StopReason};
use pi_embedded::{EventPayload, SessionEvent, SessionStatus};

/// Ordered engine events for one run.
#[derive(Clone, Default)]
pub(crate) struct EventQueue {
    inner: Arc<Mutex<QueueInner>>,
}

#[derive(Default)]
struct QueueInner {
    events: VecDeque<EngineEvent>,
    last_state: Option<RunState>,
}

impl EventQueue {
    /// Creates an empty queue.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Pushes one event. Consecutive duplicate state changes are coalesced.
    pub(crate) fn push(&self, event: EngineEvent) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let EngineEvent::StateChanged(state) = event {
            if inner.last_state == Some(state) {
                return;
            }
            inner.last_state = Some(state);
            inner.events.push_back(EngineEvent::StateChanged(state));
        } else {
            inner.events.push_back(event);
        }
    }

    /// Appends several events in order.
    pub(crate) fn extend(&self, events: impl IntoIterator<Item = EngineEvent>) {
        for event in events {
            self.push(event);
        }
    }

    /// Removes and returns every queued event.
    pub(crate) fn drain(&self) -> Vec<EngineEvent> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.events.drain(..).collect()
    }
}

/// Translates pi-embedded session events into host engine events.
///
/// The translator owns two pieces of per-run memory: whether a terminal engine
/// failure was already reported, and which completed tool call ids were already
/// published. A redelivered SDK event therefore cannot publish a second tool
/// call frame, and a failed run cannot later appear as idle.
#[derive(Default)]
pub(crate) struct EventTranslator {
    failed: bool,
    reported_failure: Option<EngineFailureKind>,
    emitted_tool_calls: HashSet<String>,
}

impl EventTranslator {
    /// Creates a translator for one run.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Translates one durable SDK session event.
    pub(crate) fn translate(&mut self, event: &SessionEvent) -> Vec<EngineEvent> {
        match &event.payload {
            EventPayload::Agent { event } => self.agent(event),
            EventPayload::Session { status, error } => self.session(*status, error.as_deref()),
            _ => Vec::new(),
        }
    }

    fn agent(&mut self, event: &AgentEvent) -> Vec<EngineEvent> {
        let mut out = Vec::new();
        match event {
            AgentEvent::MessageUpdate {
                assistant_message_event,
                ..
            } => match assistant_message_event {
                AssistantMessageEvent::TextDelta { delta, .. } if !delta.is_empty() => {
                    out.push(EngineEvent::TextDelta {
                        text: delta.clone(),
                    });
                }
                AssistantMessageEvent::Error { reason, .. } => match reason {
                    StopReason::Aborted => {
                        self.report_failure(EngineFailureKind::Interrupted, false, &mut out)
                    }
                    StopReason::Error => {
                        self.report_failure(EngineFailureKind::InvalidResponse, true, &mut out)
                    }
                    _ => {}
                },
                _ => {}
            },
            AgentEvent::MessageEnd { message } => {
                let pi_ai::Message::Assistant(assistant) = message else {
                    return out;
                };
                match assistant.stop_reason {
                    StopReason::Error => {
                        self.report_failure(EngineFailureKind::InvalidResponse, true, &mut out);
                    }
                    StopReason::Aborted => {
                        self.report_failure(EngineFailureKind::Interrupted, false, &mut out);
                    }
                    _ => {}
                }
                if matches!(
                    assistant.stop_reason,
                    StopReason::Stop | StopReason::ToolUse
                ) {
                    let text: String = assistant
                        .content
                        .iter()
                        .filter_map(pi_ai::ContentBlock::as_text)
                        .collect::<Vec<_>>()
                        .join("");
                    if !text.is_empty() {
                        out.push(EngineEvent::TextCompleted { text });
                    }
                }
                for call in assistant.tool_calls() {
                    if !self.emitted_tool_calls.insert(call.id.clone()) {
                        continue;
                    }
                    if let Some(event) = tool_call_event(call) {
                        out.push(event);
                    }
                }
            }
            _ => {}
        }
        out
    }

    fn session(&mut self, status: SessionStatus, error: Option<&str>) -> Vec<EngineEvent> {
        let mut out = Vec::new();
        if error.is_some_and(|value| !value.is_empty()) {
            if !self.failed {
                self.failed = true;
                out.push(EngineEvent::Failure {
                    failure: EngineFailureKind::InvalidResponse,
                });
                out.push(EngineEvent::StateChanged(RunState::Failed));
            }
            return out;
        }
        let state = match status {
            SessionStatus::Idle | SessionStatus::Disposed => RunState::Idle,
            SessionStatus::Running => RunState::Running,
            SessionStatus::AwaitingApproval => RunState::AwaitingApproval,
            SessionStatus::Paused => RunState::Paused,
            SessionStatus::Interrupted => RunState::Interrupted,
        };
        if self.failed && matches!(state, RunState::Idle | RunState::Interrupted) {
            return out;
        }
        out.push(EngineEvent::StateChanged(state));
        out
    }

    fn report_failure(
        &mut self,
        failure: EngineFailureKind,
        terminal: bool,
        out: &mut Vec<EngineEvent>,
    ) {
        if self.failed {
            return;
        }
        if terminal {
            self.failed = true;
        }
        if self.reported_failure != Some(failure) {
            self.reported_failure = Some(failure);
            out.push(EngineEvent::Failure { failure });
        }
        if terminal {
            out.push(EngineEvent::StateChanged(RunState::Failed));
        }
    }
}

fn tool_call_event(call: &pi_ai::ToolCall) -> Option<EngineEvent> {
    if call.arguments_error.is_some() {
        return None;
    }
    let tool = match call.name.as_str() {
        "read" => ToolName::Read,
        "search" => ToolName::Search,
        "write" => ToolName::Write,
        "edit" => ToolName::Edit,
        "bash" => ToolName::Bash,
        _ => return None,
    };
    let value = serde_json::json!({
        "tool": tool.as_str(),
        "arguments": call.arguments,
    });
    let arguments: ToolArguments = serde_json::from_value(value).ok()?;
    Some(EngineEvent::ToolCall { tool, arguments })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pi_ai::{AssistantMessage, ContentBlock, Model, ToolCall, UserContent, UserMessage};

    fn session_event(payload: EventPayload, sequence: u64) -> SessionEvent {
        SessionEvent {
            payload,
            version: 1,
            session_id: "session-test".to_owned(),
            sequence,
        }
    }

    fn user_message() -> pi_ai::Message {
        pi_ai::Message::User(UserMessage {
            content: UserContent::Text("hello".to_owned()),
            timestamp: 0,
        })
    }

    #[test]
    fn text_delta_is_translated_after_the_durable_save() {
        let mut translator = EventTranslator::new();
        let event = session_event(
            EventPayload::Agent {
                event: AgentEvent::MessageUpdate {
                    message: user_message(),
                    assistant_message_event: AssistantMessageEvent::TextDelta {
                        content_index: 0,
                        delta: "chunk".to_owned(),
                        partial: AssistantMessage::empty(&Model::default()),
                    },
                },
            },
            1,
        );
        assert_eq!(
            translator.translate(&event),
            vec![EngineEvent::TextDelta {
                text: "chunk".to_owned()
            }]
        );
    }

    #[test]
    fn completed_tool_call_arguments_are_translated_and_partial_arguments_are_not() {
        let mut translator = EventTranslator::new();
        let model = Model::default();
        let mut assistant = AssistantMessage::empty(&model);
        assistant.stop_reason = StopReason::ToolUse;
        assistant.content.push(ContentBlock::text("reading"));
        assistant.content.push(ContentBlock::ToolCall(ToolCall {
            id: "call-1".to_owned(),
            name: "read".to_owned(),
            arguments: serde_json::json!({"path": "notes.txt"})
                .as_object()
                .cloned()
                .expect("object"),
            ..ToolCall::default()
        }));
        let event = session_event(
            EventPayload::Agent {
                event: AgentEvent::MessageEnd {
                    message: pi_ai::Message::Assistant(assistant.clone()),
                },
            },
            2,
        );
        let events = translator.translate(&event);
        assert_eq!(
            events[0],
            EngineEvent::TextCompleted {
                text: "reading".to_owned()
            }
        );
        assert!(matches!(
            &events[1],
            EngineEvent::ToolCall {
                tool: ToolName::Read,
                ..
            }
        ));
        let redelivered = translator.translate(&event);
        assert!(
            !redelivered
                .iter()
                .any(|event| matches!(event, EngineEvent::ToolCall { .. })),
            "a redelivered tool frame must not be published twice"
        );

        let mut malformed = AssistantMessage::empty(&model);
        malformed.stop_reason = StopReason::ToolUse;
        malformed.content.push(ContentBlock::ToolCall(ToolCall {
            id: "call-2".to_owned(),
            name: "read".to_owned(),
            arguments_error: Some("unterminated JSON".to_owned()),
            ..ToolCall::default()
        }));
        let event = session_event(
            EventPayload::Agent {
                event: AgentEvent::MessageEnd {
                    message: pi_ai::Message::Assistant(malformed),
                },
            },
            3,
        );
        assert!(
            !translator
                .translate(&event)
                .iter()
                .any(|event| matches!(event, EngineEvent::ToolCall { .. }))
        );
    }

    #[test]
    fn a_failed_run_is_not_rewritten_as_idle() {
        let mut translator = EventTranslator::new();
        let model = Model::default();
        let mut failed = AssistantMessage::empty(&model);
        failed.stop_reason = StopReason::Error;
        failed.error_message = Some("provider raw text".to_owned());
        let event = session_event(
            EventPayload::Agent {
                event: AgentEvent::MessageEnd {
                    message: pi_ai::Message::Assistant(failed),
                },
            },
            4,
        );
        let events = translator.translate(&event);
        assert!(events.contains(&EngineEvent::Failure {
            failure: EngineFailureKind::InvalidResponse
        }));
        assert!(events.contains(&EngineEvent::StateChanged(RunState::Failed)));

        let idle = session_event(
            EventPayload::Session {
                status: SessionStatus::Idle,
                error: None,
            },
            5,
        );
        assert!(
            translator.translate(&idle).is_empty(),
            "a failed run must not later appear idle"
        );
    }
}
