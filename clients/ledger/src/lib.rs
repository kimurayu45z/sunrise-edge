#![forbid(unsafe_code)]

//! Sunrise Edge Ledger host client (S4c; see `SIGNING.md` and
//! `ARCHITECTURE.md`'s Hardware Signing Profile v1 decision records).
//!
//! This crate owns every Ledger/APDU/USB/HID dependency in this workspace
//! (`hidapi`, confined to [`hid`]) and implements the host side of the
//! frozen `SIGNING.md` device contract: exact APDU bytes/status words
//! ([`apdu`]), the provisional derivation path ([`path`]), `get
//! configuration` decoding/validation ([`configuration`]), the FIRST/
//! CONTINUE/LAST signing state machine ([`device`]), and a
//! `sunrise_edge_client::ExternalSigner` implementation ([`signer`]) that
//! performs device-reported configuration and public key/address checks
//! before every signature.
//!
//! Every type above [`hid`] is generic over the injectable
//! [`apdu::Transport`] trait, so [`fake::FakeTransport`] exercises the
//! complete protocol deterministically — APDU chunking, exact response
//! lengths and statuses, configuration/profile/flags validation, public
//! key/address identity, and disconnect/rejection/fail-closed cases —
//! without any USB/HID hardware, and with no native dependency at all.
//! Real physical hardware-in-the-loop evidence remains deferred (see
//! `SIGNING.md`, "Delivery sequence"); [`hid::HidTransport`] is a real, but
//! not yet hardware-validated, implementation of that same trait.
//!
//! [`hid::HidTransport`] and the `hidapi` dependency it wraps are behind the
//! `usb-hid` Cargo feature, off by default purely to keep this crate's (and
//! every dependent crate's) default build/test/clippy run free of any
//! native dependency at all — not because `hidapi` needs an unavailable
//! system package. This workspace pins `hidapi`'s `linux-native-basic-udev`
//! feature, which links a pure-Rust `basic-udev` implementation and needs no
//! system `libudev`/`libusb` development package, unlike its
//! `linux-static-hidraw`/`linux-static-libusb` alternatives. Enable
//! `usb-hid` explicitly to build a binary that can reach real hardware.
//!
//! No protocol crate and no `clients/rust` may depend on this crate or on
//! `hidapi` (see `ARCHITECTURE.md`'s "Non-negotiable architecture rules" and
//! DR-0088/DR-0091/DR-0092): this crate depends on `sunrise-edge-client`,
//! never the reverse.

pub mod apdu;
pub mod configuration;
pub mod device;
pub mod error;
pub mod fake;
#[cfg(feature = "usb-hid")]
pub mod hid;
pub mod path;
pub mod signer;

pub use apdu::{ApduCommand, ApduResponse, Transport};
pub use configuration::{Configuration, ConfigurationError};
pub use device::LedgerDevice;
pub use error::DeviceError;
pub use fake::{FakeTransport, FakeTransportError};
#[cfg(feature = "usb-hid")]
pub use hid::{HidTransport, HidTransportError, LEDGER_USB_VENDOR_ID};
pub use path::{DerivationPath, DerivationPathError};
pub use signer::LedgerExternalSigner;
