//! Core-class JSON-RPC HTTP server (documented subset — not full Core parity).
//!
//! See `docs/rpc.md` for methods, auth, and permanent gaps.

#![forbid(unsafe_code)]

#[doc(hidden)]
pub mod auth;
#[doc(hidden)]
pub mod blockstats;
#[doc(hidden)]
pub mod methods;
#[doc(hidden)]
pub mod server;

pub use auth::{
    default_socket_path, default_token_path, read_cookie_file, RpcAuth, RpcCookiePerms,
};
pub use methods::{
    difficulty_rpc_f64, gbt_template, HubRegtest, RpcActive, RpcContext, RpcRegtest,
};
pub use server::{
    run_rpc, RpcConfig, RpcHandle, DEFAULT_RPC_WORK_QUEUE, REST_MAX_HTTP_BODY, RPC_MAX_HTTP_BODY,
};

/// Root HTTP path for the node RPC endpoint.
pub fn node_rpc_path() -> &'static str {
    "/"
}
