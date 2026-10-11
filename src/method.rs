use std::num::NonZeroU64;

/// The two auth_akarin_v2 methods. Both peers must use the same one: its label
/// is mixed into every key derivation and transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    /// `auth_akarin_spec_a_v2`: traffic shaping uses one fixed epoch.
    SpecA,
    /// `auth_akarin_spec_time_v2`: the shaping profile and the UDP packet keys
    /// rotate every `interval_secs` of wall-clock time, so peers need clocks
    /// that agree to within one interval.
    SpecTime { interval_secs: NonZeroU64 },
}

impl Method {
    pub const SPEC_A_LABEL: &'static str = "auth_akarin_spec_a_v2";
    pub const SPEC_TIME_LABEL: &'static str = "auth_akarin_spec_time_v2";
    pub const DEFAULT_SPEC_TIME_INTERVAL: NonZeroU64 = NonZeroU64::new(3600).unwrap();

    /// `auth_akarin_spec_time_v2` with the default one-hour interval.
    pub fn spec_time() -> Self {
        Self::SpecTime {
            interval_secs: Self::DEFAULT_SPEC_TIME_INTERVAL,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::SpecA => Self::SPEC_A_LABEL,
            Self::SpecTime { .. } => Self::SPEC_TIME_LABEL,
        }
    }

    pub(crate) fn spec_time_interval(self) -> Option<u64> {
        match self {
            Self::SpecA => None,
            Self::SpecTime { interval_secs } => Some(interval_secs.get()),
        }
    }
}
