//! # Twilight Relayer SDK
//!
//! A specialized Rust SDK for building relayer services on the Twilight blockchain ecosystem.
//!
//! This crate provides comprehensive tools for:
//! - Trading operations and order management
//! - Lending services and pool management  
//! - Smart contract integration
//! - Zero-knowledge proof generation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use twilight_relayer_sdk::order::*;
//!
//! // Create and broadcast a trading order
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let tx_hash = broadcast_trade_order(tx)?;
//! # Ok(())
//! # }
//! ```

#![allow(missing_docs)]
#![allow(non_snake_case)]
#![deny(unsafe_code)]

#[macro_use]
extern crate lazy_static;
pub extern crate quisquislib;
pub extern crate transaction;
pub extern crate transactionapi;
pub extern crate twilight_client_sdk; // Updated reference
pub extern crate zkschnorr;
pub extern crate zkvm;

pub mod lend;
pub mod order;
pub mod relayer;
mod signed_integer;
pub mod verify_client_message;

pub use crate::signed_integer::SignedInteger;
