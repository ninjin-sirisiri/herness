//! Product-facing availability of automatic permission mode.

use serde::{Deserialize, Serialize};

use crate::permissions::EvaluatorAvailability;

/// Why automatic mode cannot be selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticModeUnavailableReason {
    /// No evaluator is connected or the connected evaluator is unusable.
    EvaluatorUnavailable,
}

/// Whether automatic mode can be used in the current product configuration.
///
/// This is the value a UI should display. H1 never falls back to unconditional
/// execution, a different model, or a hidden allow when an evaluator is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomaticModeCapability {
    usable: bool,
    reason: Option<AutomaticModeUnavailableReason>,
}

impl AutomaticModeCapability {
    /// Derives the capability from evaluator availability.
    pub const fn from_availability(availability: EvaluatorAvailability) -> Self {
        match availability {
            EvaluatorAvailability::Available => Self {
                usable: true,
                reason: None,
            },
            EvaluatorAvailability::Unavailable => Self {
                usable: false,
                reason: Some(AutomaticModeUnavailableReason::EvaluatorUnavailable),
            },
        }
    }

    /// Whether automatic mode can be selected.
    pub const fn usable(self) -> bool {
        self.usable
    }

    /// Why automatic mode is unusable, when it is unusable.
    pub const fn reason(self) -> Option<AutomaticModeUnavailableReason> {
        self.reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_mode_is_reported_unusable_without_an_evaluator() {
        let unavailable =
            AutomaticModeCapability::from_availability(EvaluatorAvailability::Unavailable);
        assert!(!unavailable.usable());
        assert_eq!(
            unavailable.reason(),
            Some(AutomaticModeUnavailableReason::EvaluatorUnavailable)
        );

        let available =
            AutomaticModeCapability::from_availability(EvaluatorAvailability::Available);
        assert!(available.usable());
        assert_eq!(available.reason(), None);
    }
}
