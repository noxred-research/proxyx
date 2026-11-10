//! Exit-IP quorum, reputation and light probe, and the replacement
//! rule for static IPs.
//!
//! Every service base URL is configuration, so tests (and staging) can point
//! them at local servers.

mod admit;
mod exit_ip;
mod http;
mod probe;
mod replace;
mod reputation;
mod score;
#[cfg(test)]
mod testutil;

pub use admit::{AdmitError, Admitted, Quality, Refusal, admit, assess, quality};
pub use exit_ip::{
    CheckService, ExitIp, ExitIpChecker, ExitIpConfig, ExitIpError, ExitQuery, ServiceKind,
};
pub use http::ClientError;
pub use probe::{LightProbe, Outcome, ProbeConfig, ProbeReport, Sample, TargetProbe};
pub use replace::{IpHistory, ProbeRound, ReplaceReason, ReplaceRule};
pub use reputation::{Assessment, Reputation, ReputationConfig, ScorerSlot, Verdict};
pub use reqwest::Url;
pub use score::{Flags, Score, ScoreError, Scorer, ScorerAccount, ScorerKind};
