//! Standalone Transaction v1 authentication boundary.
//!
//! This module composes three independently accepted primitives into one
//! fail-closed entrypoint:
//!
//! * the strict, standalone [`execution::decode_transaction`] canonical
//!   decoder;
//! * the committed [`protocol_config::TransactionAuthProfile`], resolved from
//!   [`protocol_config::ProtocolConfig`] through
//!   [`protocol_config::resolve_transaction_auth_profile`];
//! * the concrete ZIP-215 [`crypto::Ed25519Verifier`].
//!
//! It performs no persistence, dispatch, or `NodeEvent` wiring: it accepts
//! untrusted canonical bytes plus a caller-supplied [`TrustedTransactionContext`]
//! and returns an [`AuthenticatedTransaction`] only once every check below
//! succeeds. Nothing in this module constructs an `AuthenticatedTransaction`
//! other than [`authenticate_transaction_bytes`].
//!
//! Committing a [`protocol_config::TransactionAuthProfile`] and reaching
//! protocol version 3 is necessary but not sufficient for this boundary to
//! actually run against live traffic: no `NodeEvent` or native HTTP route
//! calls [`authenticate_transaction_bytes`] yet, and protocol version 3 must
//! not be activated on any live chain until a real transaction-processing
//! path invokes this boundary before any execution effects or storage
//! mutation. See `ARCHITECTURE.md` for the accepted decision record.

use core::fmt;
use std::error::Error;

use crypto::{
    CryptoError, Ed25519Verifier, SignatureDomain, SignatureMessageType, SignatureVerifier,
};
use execution::{ExecutionError, Transaction, decode_transaction, encode_transaction_signable};
use protocol_config::{
    AddressBinding, ProtocolConfig, ProtocolConfigError, resolve_transaction_auth_profile,
};
use protocol_types::{ChainId, Epoch, ProtocolVersion};

/// The stable, exact transaction-v1 signature message family.
///
/// This string is part of the signed byte layout via
/// [`crypto::frame_signature_message`]. Changing it changes every future
/// transaction signature and must go through the same protocol-critical
/// change process as any other wire constant.
const TRANSACTION_V1_MESSAGE_TYPE: &str = "transaction-v1";

/// Deterministic upper bound on a transaction's canonical *signable* byte
/// length (the [`execution::encode_transaction_signable`] output), enforced
/// before [`crypto::frame_signature_message`] or any verifier work may
/// allocate or hash it.
///
/// This is independent of, and intentionally tighter in the worst case than,
/// the sum of `execution`'s already-enforced per-field decode bounds
/// (`MAX_TRANSACTION_ARGS_BYTES`, `MAX_TRANSACTION_MANIFEST_ENTRIES`, and so
/// on): those bound individual attacker-controlled fields before copying
/// them out of the decoder's borrowed frame, while this bound protects the
/// separate hashing/verification computation this module performs over the
/// *combined* signable payload. A transaction that decodes successfully but
/// whose combined signable payload exceeds this bound is rejected with
/// [`TransactionAuthError::SignableTransactionTooLarge`] before any framing
/// or cryptographic call runs.
pub const MAX_TRANSACTION_SIGNABLE_BYTES: usize = 1024 * 1024;

/// Errors returned by [`authenticate_transaction_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionAuthError {
    /// The committed `TransactionAuthProfile` could not be resolved: a
    /// premature, missing, or otherwise invalid `ProtocolConfig`.
    Config(ProtocolConfigError),
    /// Strict canonical decoding of the transaction bytes failed.
    Decode(ExecutionError),
    /// The transaction's `chain_id` does not match the trusted context.
    ChainMismatch {
        /// Chain the trusted context expects.
        expected: ChainId,
        /// Chain carried by the decoded transaction.
        actual: ChainId,
    },
    /// The transaction's `protocol_version` does not match the committed
    /// `ProtocolConfig` version.
    ProtocolVersionMismatch {
        /// Version committed in `ProtocolConfig`.
        expected: ProtocolVersion,
        /// Version carried by the decoded transaction.
        actual: ProtocolVersion,
    },
    /// The transaction's `epoch` does not match the trusted context.
    EpochMismatch {
        /// Epoch the trusted context expects.
        expected: Epoch,
        /// Epoch carried by the decoded transaction.
        actual: Epoch,
    },
    /// The canonical signable payload exceeded
    /// [`MAX_TRANSACTION_SIGNABLE_BYTES`] before any framing or
    /// cryptographic operation ran.
    SignableTransactionTooLarge {
        /// Actual signable byte length.
        actual: usize,
        /// Maximum permitted signable byte length.
        maximum: usize,
    },
    /// A malformed verification key, malformed signature length, or
    /// signature-domain scheme mismatch was rejected by the cryptographic
    /// layer. This is distinct from [`TransactionAuthError::InvalidTransactionSignature`],
    /// which reports a well-formed but cryptographically invalid signature.
    Crypto(CryptoError),
    /// A well-formed signature did not verify against the transaction's
    /// signable payload and the trusted signing context.
    InvalidTransactionSignature,
}

impl fmt::Display for TransactionAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "transaction auth profile resolution failed: {error}"),
            Self::Decode(error) => write!(f, "transaction decoding failed: {error}"),
            Self::ChainMismatch { expected, actual } => write!(
                f,
                "transaction chain {actual} does not match trusted chain {expected}"
            ),
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                f,
                "transaction protocol version {} does not match committed protocol version {}",
                actual.get(),
                expected.get()
            ),
            Self::EpochMismatch { expected, actual } => write!(
                f,
                "transaction epoch {} does not match trusted epoch {}",
                actual.get(),
                expected.get()
            ),
            Self::SignableTransactionTooLarge { actual, maximum } => write!(
                f,
                "transaction signable payload is {actual} bytes, maximum is {maximum}"
            ),
            Self::Crypto(error) => write!(f, "transaction signature cryptography error: {error}"),
            Self::InvalidTransactionSignature => {
                write!(f, "transaction signature did not verify")
            }
        }
    }
}

impl Error for TransactionAuthError {}

/// The explicit, caller-supplied trusted signing/replay context.
///
/// `chain_id` and `epoch` are supplied directly because they describe the
/// specific event/request being authenticated, not a committed protocol
/// artifact. Protocol version authority comes *only* from the referenced
/// [`ProtocolConfig`]: this type deliberately carries no separate
/// caller-supplied protocol version field, so a caller cannot present one
/// value to [`authenticate_transaction_bytes`] while `ProtocolConfig` commits
/// a different one.
#[derive(Clone, Debug)]
pub struct TrustedTransactionContext<'a> {
    chain_id: ChainId,
    epoch: Epoch,
    protocol_config: &'a ProtocolConfig,
}

impl<'a> TrustedTransactionContext<'a> {
    /// Builds a trusted context from the expected chain, expected epoch, and
    /// the committed protocol configuration.
    #[must_use]
    pub fn new(chain_id: ChainId, epoch: Epoch, protocol_config: &'a ProtocolConfig) -> Self {
        Self {
            chain_id,
            epoch,
            protocol_config,
        }
    }

    /// Returns the expected chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the expected epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the referenced committed protocol configuration.
    #[must_use]
    pub const fn protocol_config(&self) -> &ProtocolConfig {
        self.protocol_config
    }

    /// Returns the sole authority for the expected protocol version: the
    /// committed `ProtocolConfig`'s own `protocol_version`.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_config.protocol_version
    }
}

/// A [`Transaction`] that has been strictly decoded from canonical bytes and
/// whose signature has been cryptographically verified against a
/// [`TrustedTransactionContext`].
///
/// The inner transaction is private and has no public constructor: the only
/// way to obtain a value of this type is a successful
/// [`authenticate_transaction_bytes`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedTransaction {
    transaction: Transaction,
}

impl AuthenticatedTransaction {
    /// Returns a read-only reference to the authenticated transaction.
    #[must_use]
    pub const fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Consumes this wrapper and returns the authenticated transaction.
    #[must_use]
    pub fn into_transaction(self) -> Transaction {
        self.transaction
    }
}

/// Authenticates one canonical Transaction v1 byte payload against a trusted
/// context, returning an [`AuthenticatedTransaction`] only on a fully
/// verified `Ok(true)` result.
///
/// Fail-closed order of operations:
///
/// 1. Resolve the committed [`protocol_config::TransactionAuthProfile`] from
///    `context.protocol_config()`; a premature, missing, or otherwise
///    invalid configuration rejects before any byte of `input` is decoded.
/// 2. Strictly decode `input` with [`execution::decode_transaction`].
/// 3. Compare the decoded transaction's `chain_id`, `protocol_version`, and
///    `epoch` against the trusted context/config, rejecting any mismatch
///    with a typed error before any cryptographic work runs.
/// 4. Build the [`crypto::SignatureDomain`] solely from the trusted context
///    and the resolved profile, using the exact stable message family
///    `"transaction-v1"`.
/// 5. Encode the signable transaction payload (the signature field
///    excluded) and reject it with
///    [`TransactionAuthError::SignableTransactionTooLarge`] if it exceeds
///    [`MAX_TRANSACTION_SIGNABLE_BYTES`], before any framing or verifier
///    call can allocate or hash it.
/// 6. Dispatch on the resolved profile's [`AddressBinding`]. Only
///    [`AddressBinding::AddressIsPublicKey`] is implemented: the
///    transaction's exact 32-byte `sender` is used directly as the Ed25519
///    verification key. This match is exhaustive over the closed
///    `AddressBinding` enum, so an unimplemented future binding fails to
///    compile rather than silently falling back.
/// 7. Verify the signature with the committed [`crypto::Ed25519Verifier`].
///    A malformed verification key or malformed signature length surfaces as
///    a distinct [`TransactionAuthError::Crypto`]; a well-formed but
///    cryptographically invalid signature surfaces as
///    [`TransactionAuthError::InvalidTransactionSignature`].
/// 8. Return [`AuthenticatedTransaction`] only when verification returns
///    `Ok(true)`.
pub fn authenticate_transaction_bytes(
    input: &[u8],
    context: &TrustedTransactionContext<'_>,
) -> Result<AuthenticatedTransaction, TransactionAuthError> {
    let profile = resolve_transaction_auth_profile(context.protocol_config())
        .map_err(TransactionAuthError::Config)?;

    let transaction = decode_transaction(input).map_err(TransactionAuthError::Decode)?;

    if &transaction.chain_id != context.chain_id() {
        return Err(TransactionAuthError::ChainMismatch {
            expected: context.chain_id().clone(),
            actual: transaction.chain_id.clone(),
        });
    }
    if transaction.protocol_version != context.protocol_version() {
        return Err(TransactionAuthError::ProtocolVersionMismatch {
            expected: context.protocol_version(),
            actual: transaction.protocol_version,
        });
    }
    if transaction.epoch != context.epoch() {
        return Err(TransactionAuthError::EpochMismatch {
            expected: context.epoch(),
            actual: transaction.epoch,
        });
    }

    let domain = SignatureDomain {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        message_type: SignatureMessageType::new(TRANSACTION_V1_MESSAGE_TYPE)
            .map_err(TransactionAuthError::Crypto)?,
        signature_scheme_id: profile.signature_scheme_id(),
    };

    let signable =
        encode_transaction_signable(&transaction).map_err(TransactionAuthError::Decode)?;
    if signable.len() > MAX_TRANSACTION_SIGNABLE_BYTES {
        return Err(TransactionAuthError::SignableTransactionTooLarge {
            actual: signable.len(),
            maximum: MAX_TRANSACTION_SIGNABLE_BYTES,
        });
    }

    let verified = match profile.address_binding() {
        AddressBinding::AddressIsPublicKey => {
            let verifier = Ed25519Verifier::from_verifying_key_bytes(transaction.sender.as_bytes())
                .map_err(TransactionAuthError::Crypto)?;
            verifier
                .verify_canonical(&domain, &signable, &transaction.signature)
                .map_err(TransactionAuthError::Crypto)?
        }
    };

    if !verified {
        return Err(TransactionAuthError::InvalidTransactionSignature);
    }

    Ok(AuthenticatedTransaction { transaction })
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{AccessEntry, AccessManifest};
    use ed25519_zebra::SigningKey;
    use execution::encode_transaction;
    use objects::{AccessMode, Address, ObjectId, ObjectRef};
    use protocol_config::{DomainPlacementManifest, TransactionAuthProfile};
    use protocol_types::{AtomicityDomainId, Digest32, HashAlgorithmId};

    /// A dev-only deterministic signer built directly on the exact-pinned
    /// workspace `ed25519-zebra` `SigningKey`. This is test infrastructure
    /// only: no production signer exists in this workspace, matching
    /// `crypto`'s and `ARCHITECTURE.md`'s documented invariant.
    fn dev_signing_key(seed: u8) -> SigningKey {
        SigningKey::from([seed; 32])
    }

    fn dev_sender_address(signing_key: &SigningKey) -> Address {
        let verification_key = ed25519_zebra::VerificationKey::from(signing_key);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(verification_key.as_ref());
        Address::new(bytes)
    }

    fn chain_id() -> ChainId {
        ChainId::new("sunrise-devnet").unwrap()
    }

    fn active_protocol_config() -> ProtocolConfig {
        let mut config = ProtocolConfig::genesis();
        config.protocol_version = ProtocolVersion::new(3);
        config.domain_placement = Some(
            DomainPlacementManifest::single_domain(
                1,
                AtomicityDomainId::new([0x22; 32]).unwrap(),
                Epoch::new(0),
            )
            .unwrap(),
        );
        config.transaction_auth_profile =
            Some(TransactionAuthProfile::ed25519_address_is_public_key());
        config
    }

    fn sample_object_ref(id_byte: u8) -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([id_byte; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [id_byte; 32]),
        }
    }

    fn unsigned_transaction(sender: Address, chain: ChainId, epoch: Epoch) -> Transaction {
        let mut manifest = AccessManifest::new();
        manifest.push(AccessEntry {
            object_ref: sample_object_ref(0x11),
            mode: AccessMode::Read,
        });

        Transaction {
            chain_id: chain,
            protocol_version: ProtocolVersion::new(3),
            epoch,
            sender,
            nonce: 7,
            access_manifest: manifest,
            module_ref: sample_object_ref(0xDD),
            entrypoint: "transfer".to_string(),
            args: vec![1, 2, 3, 4],
            gas_limit: 100_000,
            fee_payment: None,
            signature: Vec::new(),
        }
    }

    /// Signs `tx` under the exact production [`SignatureDomain`] that
    /// `authenticate_transaction_bytes` itself builds (`tx.chain_id`,
    /// protocol version 3, `tx.epoch`, message family `"transaction-v1"`,
    /// Ed25519), by framing `tx`'s signable payload through
    /// [`sign_under_domain`]. Production verification runs
    /// `crypto::frame_signature_message(domain, signable)` before checking
    /// the signature, so signing the raw signable bytes directly would not
    /// exercise the real verified payload; returns the fully encoded
    /// transaction bytes.
    fn signed_transaction_bytes(signing_key: &SigningKey, tx: &Transaction) -> Vec<u8> {
        let signable = encode_transaction_signable(tx).unwrap();
        let domain = production_domain(tx.chain_id.clone(), tx.epoch);
        let mut signed = tx.clone();
        signed.signature = sign_under_domain(signing_key, &domain, &signable);
        encode_transaction(&signed).unwrap()
    }

    /// Signs `signable` under an explicitly supplied [`SignatureDomain`],
    /// used both by [`signed_transaction_bytes`] (the production domain) and
    /// by the domain-replay tests (a deliberately wrong domain).
    fn sign_under_domain(
        signing_key: &SigningKey,
        domain: &SignatureDomain,
        signable: &[u8],
    ) -> Vec<u8> {
        let framed = crypto::frame_signature_message(domain, signable).unwrap();
        let signature = signing_key.sign(&framed);
        signature.to_bytes().to_vec()
    }

    fn production_domain(chain: ChainId, epoch: Epoch) -> SignatureDomain {
        SignatureDomain {
            chain_id: chain,
            protocol_version: ProtocolVersion::new(3),
            epoch,
            message_type: SignatureMessageType::new(TRANSACTION_V1_MESSAGE_TYPE).unwrap(),
            signature_scheme_id: protocol_types::SignatureSchemeId::Ed25519,
        }
    }

    /// 32 bytes that are a well-formed length but not a valid Edwards25519
    /// point encoding: 31 bytes of `0xff` followed by `0x00`, matching
    /// `crypto::ed25519::tests::malformed_verification_key_is_rejected`.
    fn malformed_ed25519_sender() -> Address {
        let mut bytes = [0xff_u8; 32];
        bytes[31] = 0x00;
        Address::new(bytes)
    }

    // ── happy path ──────────────────────────────────────────────────────

    #[test]
    fn deterministic_real_ed25519_happy_path_authenticates() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x01);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        let bytes = signed_transaction_bytes(&signing_key, &tx);
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        let authenticated = authenticate_transaction_bytes(&bytes, &context).unwrap();

        assert_eq!(authenticated.transaction().nonce, 7);
        assert_eq!(authenticated.clone().into_transaction().nonce, 7);
    }

    #[test]
    fn authentication_is_deterministic_across_repeated_calls() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x02);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        let bytes = signed_transaction_bytes(&signing_key, &tx);
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        let first = authenticate_transaction_bytes(&bytes, &context).unwrap();
        let second = authenticate_transaction_bytes(&bytes, &context).unwrap();

        assert_eq!(first, second);
    }

    // ── wrong / invalid signature ──────────────────────────────────────

    #[test]
    fn wrong_signature_is_rejected_as_invalid_transaction_signature() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x03);
        let other_signing_key = dev_signing_key(0x04);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        // Sign with a *different* key than the transaction's sender.
        let bytes = signed_transaction_bytes(&other_signing_key, &tx);
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::InvalidTransactionSignature)
        );
    }

    // ── malformed key / signature remain typed crypto errors ───────────

    #[test]
    fn malformed_verification_key_is_a_typed_crypto_error() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x05);
        let tx = unsigned_transaction(malformed_ed25519_sender(), chain_id(), Epoch::new(5));
        let bytes = signed_transaction_bytes(&signing_key, &tx);
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::Crypto(
                CryptoError::MalformedVerificationKey
            ))
        );
    }

    #[test]
    fn malformed_signature_length_is_a_typed_crypto_error() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x06);
        let sender = dev_sender_address(&signing_key);
        let mut tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        tx.signature = vec![0x11; 10];
        let bytes = encode_transaction(&tx).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::Crypto(
                CryptoError::InvalidSignatureLength(10)
            ))
        );
    }

    // ── mismatches reject before cryptographic work ─────────────────────

    #[test]
    fn chain_mismatch_rejects_before_cryptographic_work_even_with_malformed_key_and_signature() {
        let config = active_protocol_config();
        let mut tx = unsigned_transaction(
            malformed_ed25519_sender(),
            ChainId::new("wrong-chain").unwrap(),
            Epoch::new(5),
        );
        tx.signature = vec![0x11; 3]; // also an invalid signature length
        let bytes = encode_transaction(&tx).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::ChainMismatch {
                expected: chain_id(),
                actual: ChainId::new("wrong-chain").unwrap(),
            })
        );
    }

    #[test]
    fn protocol_version_mismatch_rejects_before_cryptographic_work() {
        let config = active_protocol_config();
        let mut tx = unsigned_transaction(malformed_ed25519_sender(), chain_id(), Epoch::new(5));
        tx.protocol_version = ProtocolVersion::new(4);
        tx.signature = vec![0x11; 3];
        let bytes = encode_transaction(&tx).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::ProtocolVersionMismatch {
                expected: ProtocolVersion::new(3),
                actual: ProtocolVersion::new(4),
            })
        );
    }

    #[test]
    fn epoch_mismatch_rejects_before_cryptographic_work() {
        let config = active_protocol_config();
        let mut tx = unsigned_transaction(malformed_ed25519_sender(), chain_id(), Epoch::new(5));
        tx.epoch = Epoch::new(6);
        tx.signature = vec![0x11; 3];
        let bytes = encode_transaction(&tx).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::EpochMismatch {
                expected: Epoch::new(5),
                actual: Epoch::new(6),
            })
        );
    }

    // ── domain replay across chain / version / epoch / message family ──

    #[test]
    fn a_signature_produced_under_a_different_chain_domain_fails() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x07);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        let signable = encode_transaction_signable(&tx).unwrap();
        let wrong_domain = SignatureDomain {
            chain_id: ChainId::new("another-chain").unwrap(),
            ..production_domain(chain_id(), Epoch::new(5))
        };
        let mut signed = tx.clone();
        signed.signature = sign_under_domain(&signing_key, &wrong_domain, &signable);
        let bytes = encode_transaction(&signed).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::InvalidTransactionSignature)
        );
    }

    #[test]
    fn a_signature_produced_under_a_different_protocol_version_domain_fails() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x08);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        let signable = encode_transaction_signable(&tx).unwrap();
        let wrong_domain = SignatureDomain {
            protocol_version: ProtocolVersion::new(99),
            ..production_domain(chain_id(), Epoch::new(5))
        };
        let mut signed = tx.clone();
        signed.signature = sign_under_domain(&signing_key, &wrong_domain, &signable);
        let bytes = encode_transaction(&signed).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::InvalidTransactionSignature)
        );
    }

    #[test]
    fn a_signature_produced_under_a_different_epoch_domain_fails() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x09);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        let signable = encode_transaction_signable(&tx).unwrap();
        let wrong_domain = SignatureDomain {
            epoch: Epoch::new(999),
            ..production_domain(chain_id(), Epoch::new(5))
        };
        let mut signed = tx.clone();
        signed.signature = sign_under_domain(&signing_key, &wrong_domain, &signable);
        let bytes = encode_transaction(&signed).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::InvalidTransactionSignature)
        );
    }

    #[test]
    fn a_signature_produced_under_a_different_message_family_fails() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x0A);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        let signable = encode_transaction_signable(&tx).unwrap();
        let wrong_domain = SignatureDomain {
            message_type: SignatureMessageType::new("transaction-v2").unwrap(),
            ..production_domain(chain_id(), Epoch::new(5))
        };
        let mut signed = tx.clone();
        signed.signature = sign_under_domain(&signing_key, &wrong_domain, &signable);
        let bytes = encode_transaction(&signed).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::InvalidTransactionSignature)
        );
    }

    // ── premature / missing profile / config validation fails closed ────

    #[test]
    fn premature_protocol_version_fails_closed_before_decoding() {
        let mut config = ProtocolConfig::genesis();
        config.protocol_version = ProtocolVersion::new(1);
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        // Malformed input bytes: if decoding ran before profile resolution,
        // this would surface as `TransactionAuthError::Decode`, not
        // `Config`.
        assert_eq!(
            authenticate_transaction_bytes(&[0xFF, 0xFF, 0xFF], &context),
            Err(TransactionAuthError::Config(
                ProtocolConfigError::TransactionAuthProfileNotActive(ProtocolVersion::new(1))
            ))
        );
    }

    #[test]
    fn missing_transaction_auth_profile_fails_closed() {
        let mut config = ProtocolConfig::genesis();
        config.protocol_version = ProtocolVersion::new(3);
        config.domain_placement = Some(
            DomainPlacementManifest::single_domain(
                1,
                AtomicityDomainId::new([0x22; 32]).unwrap(),
                Epoch::new(0),
            )
            .unwrap(),
        );
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&[0xFF, 0xFF, 0xFF], &context),
            Err(TransactionAuthError::Config(
                ProtocolConfigError::MissingTransactionAuthProfile
            ))
        );
    }

    #[test]
    fn invalid_config_unrelated_to_transaction_auth_fails_closed() {
        // protocol_version 3 with a committed profile but no domain
        // placement manifest: invalid for a reason unrelated to
        // transaction authentication.
        let mut config = ProtocolConfig::genesis();
        config.protocol_version = ProtocolVersion::new(3);
        config.transaction_auth_profile =
            Some(TransactionAuthProfile::ed25519_address_is_public_key());
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&[0xFF, 0xFF, 0xFF], &context),
            Err(TransactionAuthError::Config(
                ProtocolConfigError::MissingDomainPlacement
            ))
        );
    }

    // ── exact signable bound behavior ────────────────────────────────────

    #[test]
    fn oversized_signable_payload_is_rejected_before_verifier_work() {
        let config = active_protocol_config();
        // A malformed sender: if the size bound ran *after* verifier
        // construction, this would surface as
        // `TransactionAuthError::Crypto(MalformedVerificationKey)` instead.
        let mut tx = unsigned_transaction(malformed_ed25519_sender(), chain_id(), Epoch::new(5));
        // `execution::MAX_TRANSACTION_ARGS_BYTES` alone already equals
        // `MAX_TRANSACTION_SIGNABLE_BYTES`; every other signable field adds
        // strictly more bytes, so this decodes successfully yet pushes the
        // combined signable payload over the bound.
        tx.args = vec![0xAB; execution::MAX_TRANSACTION_ARGS_BYTES];
        tx.signature = vec![0x11; 3]; // also an invalid signature length
        let bytes = encode_transaction(&tx).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        let signable_len = encode_transaction_signable(&tx).unwrap().len();
        assert!(signable_len > MAX_TRANSACTION_SIGNABLE_BYTES);

        assert_eq!(
            authenticate_transaction_bytes(&bytes, &context),
            Err(TransactionAuthError::SignableTransactionTooLarge {
                actual: signable_len,
                maximum: MAX_TRANSACTION_SIGNABLE_BYTES,
            })
        );

        // Sanity check: the same malformed sender, at a signable size within
        // the bound, does reach (and fail at) verifier construction. This
        // proves the prior assertion is evidence of ordering, not merely
        // that a malformed key always yields `SignableTransactionTooLarge`.
        let mut small_tx =
            unsigned_transaction(malformed_ed25519_sender(), chain_id(), Epoch::new(5));
        small_tx.signature = vec![0x11; 3];
        let small_bytes = encode_transaction(&small_tx).unwrap();
        assert_eq!(
            authenticate_transaction_bytes(&small_bytes, &context),
            Err(TransactionAuthError::Crypto(
                CryptoError::MalformedVerificationKey
            ))
        );
    }

    #[test]
    fn signable_payload_at_exact_bound_authenticates_successfully() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x0C);
        let sender = dev_sender_address(&signing_key);

        // Measure this transaction shape's signable overhead with empty
        // `args` (every field's length prefix is a fixed-width `u32`, so
        // padding `args` by exactly `N` bytes grows the signable payload by
        // exactly `N` bytes), then pad `args` so the final signable length
        // lands exactly on `MAX_TRANSACTION_SIGNABLE_BYTES`.
        let mut tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        tx.args = Vec::new();
        let overhead = encode_transaction_signable(&tx).unwrap().len();
        assert!(overhead < MAX_TRANSACTION_SIGNABLE_BYTES);
        let args_len = MAX_TRANSACTION_SIGNABLE_BYTES - overhead;
        assert!(args_len <= execution::MAX_TRANSACTION_ARGS_BYTES);
        tx.args = vec![0xCD; args_len];

        let signable_len = encode_transaction_signable(&tx).unwrap().len();
        assert_eq!(signable_len, MAX_TRANSACTION_SIGNABLE_BYTES);

        let bytes = signed_transaction_bytes(&signing_key, &tx);
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert!(authenticate_transaction_bytes(&bytes, &context).is_ok());
    }

    // ── strict canonical bytes only ─────────────────────────────────────

    #[test]
    fn malformed_bytes_fail_through_execution_error() {
        let config = active_protocol_config();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        let result = authenticate_transaction_bytes(&[0x00, 0x01, 0x02], &context);
        assert!(matches!(result, Err(TransactionAuthError::Decode(_))));
    }

    #[test]
    fn alternate_representation_of_a_valid_transaction_fails_through_execution_error() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x0D);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        let bytes = signed_transaction_bytes(&signing_key, &tx);

        // Append a trailing byte: still starts with a strictly valid frame,
        // but is no longer the exact canonical encoding.
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&trailing, &context),
            Err(TransactionAuthError::Decode(
                ExecutionError::CanonicalDecoding(
                    canonical_encoding::CanonicalDecodingError::TrailingBytes(1)
                )
            ))
        );
    }

    // ── signature framing / field coverage ───────────────────────────────

    #[test]
    fn signature_field_does_not_cover_itself() {
        let sender = Address::new([0xCC; 32]);
        let mut left = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        left.signature = vec![0xAA; 64];
        let mut right = left.clone();
        right.signature = vec![0xBB; 32];

        assert_eq!(
            encode_transaction_signable(&left).unwrap(),
            encode_transaction_signable(&right).unwrap()
        );
    }

    #[test]
    fn changing_any_signable_field_invalidates_authentication() {
        let config = active_protocol_config();
        let signing_key = dev_signing_key(0x0E);
        let sender = dev_sender_address(&signing_key);
        let tx = unsigned_transaction(sender, chain_id(), Epoch::new(5));
        let bytes = signed_transaction_bytes(&signing_key, &tx);
        let mut signed = decode_transaction(&bytes).unwrap();

        // Mutate a signable field (nonce) while keeping the original
        // signature, then re-encode and re-check.
        signed.nonce = signed.nonce.wrapping_add(1);
        let tampered = encode_transaction(&signed).unwrap();
        let context = TrustedTransactionContext::new(chain_id(), Epoch::new(5), &config);

        assert_eq!(
            authenticate_transaction_bytes(&tampered, &context),
            Err(TransactionAuthError::InvalidTransactionSignature)
        );
    }
}
