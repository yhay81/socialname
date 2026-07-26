#![forbid(unsafe_code)]

mod classify;
mod http;
mod search;
mod types;

pub use classify::classify;
pub use http::{
    ManagedEmailGatewayClient, ManagedEmailGatewayError, ManagedEmailGatewayRequest,
    ManagedEmailGatewayResponse, ManagedWebhookClient, ManagedWebhookError, ManagedWebhookRequest,
    ManagedWebhookResponse, ProbeClient,
};
pub use search::SearchEngine;
pub use types::{Classification, MatcherTrace, ProbeResponse, ProbeSummary, SearchResult};
