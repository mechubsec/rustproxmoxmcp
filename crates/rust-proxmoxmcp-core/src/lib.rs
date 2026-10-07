//! Proxmox VE domain logic for `rust-proxmoxmcp`.
//!
//! This crate holds everything vendor-shaped and nothing MCP-shaped: cluster
//! inventory, guest resolution, the authorization spine, and the read catalog.
//! The binary crate owns transport, tool registration, and CLI.
//!
//! # The authorization spine
//!
//! Proxmox has no candidate configuration, so change control keys on the
//! identity of the target rather than on a config diff. Every mutating API in
//! this crate takes an `AuthorizedGuest`, a type with no public constructor
//! produced only by `resolve::authorize`. A caller that skips authorization
//! does not compile.

pub mod authorized;
pub mod catalog;
pub mod client;
pub mod error;
pub mod fingerprint;
pub mod firewall;
pub mod grant;
pub mod guests;
pub mod ha_rules;
pub mod inventory;
pub mod preview;
pub mod protect;
pub mod resolve;
pub mod selector;
pub mod task;
pub mod tier;
pub mod waiver;

#[cfg(feature = "testing")]
pub mod testing;

pub use authorized::AuthorizedGuest;
pub use client::ProxmoxClient;
pub use error::ProxmoxError;
pub use grant::{ProxmoxAction, ProxmoxGrant};
pub use inventory::{Cluster, ClusterInventory, ClusterPolicy};
pub use protect::{Protection, ProtectionReason};
pub use resolve::Intent;
pub use resolve::{GuestIndex, ResolvedGuest};
pub use selector::{GuestType, Selector};
pub use tier::Tier;
