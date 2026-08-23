#![forbid(unsafe_code)]

//! Event-driven shared-object consensus.
//!
//! This crate implements a deterministic chained-HotStuff state machine. Each
//! invocation consumes one authenticated event and an explicit persisted
//! [`ConsensusState`], then returns the next state plus outbound messages and
//! newly committed blocks. It does not spawn tasks, own sockets, or rely on
//! process memory surviving between invocations.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct, encode_digest32};
use core::fmt;
use crypto::{CryptoError, SignatureDomain, SignatureMessageType, frame_signature_message};
use hashing::{HashSuiteResolver, HashingError};
use protocol_types::{
    ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion, SignatureSchemeId, ValidatorId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use validator_set::{ValidatorSet, ValidatorSetError};

const PROPOSAL_TYPE_ID: u16 = 0xD001;
const VOTE_PAYLOAD_TYPE_ID: u16 = 0xD002;
const VOTE_TYPE_ID: u16 = 0xD003;
const CERTIFICATE_TYPE_ID: u16 = 0xD004;
const PARAMETERS_TYPE_ID: u16 = 0xD005;
const ENCODING_VERSION: u16 = 1;
const PROPOSAL_MESSAGE_TYPE: &str = "shared-consensus-proposal-v1";
const VOTE_MESSAGE_TYPE: &str = "shared-consensus-vote-v1";
const MAX_SIGNATURE_BYTES: usize = 4096;
const MAX_BLOCK_TRANSACTIONS_LIMIT: u32 = 16_384;
const MAX_FUTURE_VIEW_GAP: u64 = 64;
const RETAIN_COMMITTED_HEIGHTS: u64 = 2;

/// Stable identifier for the canonical consensus protocol.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConsensusProtocolId {
    /// Event-driven three-chain HotStuff with rotating leaders.
    ChainedHotStuffV1 = 0x0001,
}

impl ConsensusProtocolId {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Consensus parameters committed by protocol configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusParameters {
    /// Selected protocol implementation.
    pub protocol: ConsensusProtocolId,
    /// Maximum transaction digests in one proposal.
    pub max_block_transactions: u32,
    /// Local view timeout used to validate externally delivered ticks.
    pub view_timeout_millis: u64,
}

impl ConsensusParameters {
    /// Conservative genesis parameters.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            protocol: ConsensusProtocolId::ChainedHotStuffV1,
            max_block_transactions: 1024,
            view_timeout_millis: 10_000,
        }
    }

    /// Validates resource and timeout bounds.
    pub fn validate(self) -> Result<(), ConsensusError> {
        if self.max_block_transactions == 0
            || self.max_block_transactions > MAX_BLOCK_TRANSACTIONS_LIMIT
        {
            return Err(ConsensusError::InvalidMaxBlockTransactions(
                self.max_block_transactions,
            ));
        }
        if self.view_timeout_millis == 0 {
            return Err(ConsensusError::ZeroViewTimeout);
        }
        Ok(())
    }
}

/// Errors returned by shared-object consensus processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Domain-separated hashing failed.
    Hashing(HashingError),
    /// Signature framing failed.
    Crypto(CryptoError),
    /// Validator-set validation failed.
    ValidatorSet(ValidatorSetError),
    /// A signer or verifier adapter failed.
    Authenticator(String),
    /// Validator set epoch differs from the consensus epoch.
    ValidatorSetEpochMismatch { expected: Epoch, actual: Epoch },
    /// Hash resolver chain differs from the consensus chain.
    HashChainMismatch,
    /// Hash resolver protocol version differs from the consensus version.
    HashProtocolVersionMismatch,
    /// The local signer is not in the active validator set.
    UnknownValidator(ValidatorId),
    /// A message carries the wrong chain, protocol version, or epoch.
    ContextMismatch,
    /// A proposal was not produced by the deterministic leader for its view.
    InvalidLeader {
        /// View being proposed.
        view: u64,
        /// Expected leader.
        expected: ValidatorId,
        /// Leader carried by the proposal.
        actual: ValidatorId,
    },
    /// A view or height that must be non-zero was zero.
    ZeroViewOrHeight,
    /// A proposal height does not directly extend its justify certificate.
    InvalidProposalHeight,
    /// A proposal view does not advance beyond its justify certificate.
    InvalidProposalView,
    /// A message is too far ahead of local state to retain safely.
    FutureView { current: u64, received: u64 },
    /// A proposal is older than local state and is not already certified.
    StaleProposal { current: u64, received: u64 },
    /// A proposal contains too many transaction digests.
    TooManyTransactions(usize),
    /// Configured maximum block size is invalid.
    InvalidMaxBlockTransactions(u32),
    /// View timeout must be non-zero.
    ZeroViewTimeout,
    /// A signature was empty or exceeded the protocol bound.
    InvalidSignatureLength(usize),
    /// A validator used a signature scheme other than its registered scheme.
    SignatureSchemeMismatch(ValidatorId),
    /// Signature verification failed.
    InvalidSignature(ValidatorId),
    /// A non-genesis certificate did not contain a quorum.
    InsufficientQuorum { actual: u64, required: u64 },
    /// Certificate votes were duplicated or not in canonical order.
    NonCanonicalCertificateVotes,
    /// Certificate vote fields do not match the certificate header.
    CertificateVoteMismatch,
    /// A certificate header does not match the known proposal it names.
    CertificateProposalMismatch,
    /// Genesis certificate fields do not match the configured anchor.
    InvalidGenesisCertificate,
    /// The proposal does not satisfy the HotStuff locked-certificate rule.
    UnsafeProposal,
    /// This validator already voted for another proposal in the same view.
    AlreadyVoted {
        /// View containing the conflict.
        view: u64,
        /// Previously voted proposal.
        previous: Digest32,
        /// Newly presented proposal.
        conflicting: Digest32,
    },
    /// A signed validator vote equivocates within one view.
    Equivocation {
        /// Equivocating validator.
        validator: ValidatorId,
        /// Equivocated view.
        view: u64,
        /// First observed proposal.
        first: Digest32,
        /// Second observed proposal.
        second: Digest32,
    },
    /// Arithmetic overflow would make a transition ambiguous.
    ArithmeticOverflow,
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::Hashing(error) => error.fmt(f),
            Self::Crypto(error) => error.fmt(f),
            Self::ValidatorSet(error) => error.fmt(f),
            Self::Authenticator(error) => write!(f, "consensus authenticator failed: {error}"),
            Self::ValidatorSetEpochMismatch { expected, actual } => write!(
                f,
                "validator set epoch {} does not match consensus epoch {}",
                actual.get(),
                expected.get()
            ),
            Self::HashChainMismatch => write!(f, "hash resolver chain does not match consensus"),
            Self::HashProtocolVersionMismatch => {
                write!(f, "hash resolver protocol version does not match consensus")
            }
            Self::UnknownValidator(id) => write!(f, "validator {id} is not in the active set"),
            Self::ContextMismatch => write!(f, "consensus message context mismatch"),
            Self::InvalidLeader {
                view,
                expected,
                actual,
            } => write!(
                f,
                "invalid leader for view {view}: expected {expected}, got {actual}"
            ),
            Self::ZeroViewOrHeight => write!(f, "consensus view and height must be non-zero"),
            Self::InvalidProposalHeight => {
                write!(f, "proposal height does not extend its justify certificate")
            }
            Self::InvalidProposalView => {
                write!(f, "proposal view does not advance its justify certificate")
            }
            Self::FutureView { current, received } => write!(
                f,
                "consensus view {received} is too far ahead of local view {current}"
            ),
            Self::StaleProposal { current, received } => write!(
                f,
                "proposal view {received} is older than local view {current}"
            ),
            Self::TooManyTransactions(count) => {
                write!(f, "proposal contains too many transactions: {count}")
            }
            Self::InvalidMaxBlockTransactions(count) => {
                write!(f, "invalid maximum block transaction count: {count}")
            }
            Self::ZeroViewTimeout => write!(f, "consensus view timeout must be non-zero"),
            Self::InvalidSignatureLength(length) => {
                write!(f, "invalid consensus signature length: {length}")
            }
            Self::SignatureSchemeMismatch(id) => {
                write!(f, "validator {id} used an unexpected signature scheme")
            }
            Self::InvalidSignature(id) => write!(f, "invalid signature from validator {id}"),
            Self::InsufficientQuorum { actual, required } => write!(
                f,
                "certificate voting power {actual} is below quorum {required}"
            ),
            Self::NonCanonicalCertificateVotes => {
                write!(f, "certificate votes are not in canonical validator order")
            }
            Self::CertificateVoteMismatch => {
                write!(f, "certificate vote does not match its header")
            }
            Self::CertificateProposalMismatch => {
                write!(f, "certificate header does not match its known proposal")
            }
            Self::InvalidGenesisCertificate => write!(f, "invalid genesis certificate"),
            Self::UnsafeProposal => write!(f, "proposal violates the locked-certificate rule"),
            Self::AlreadyVoted {
                view,
                previous,
                conflicting,
            } => write!(
                f,
                "already voted in view {view}: previous {previous}, conflicting {conflicting}"
            ),
            Self::Equivocation {
                validator,
                view,
                first,
                second,
            } => write!(
                f,
                "validator {validator} equivocated in view {view}: {first} and {second}"
            ),
            Self::ArithmeticOverflow => write!(f, "consensus arithmetic overflow"),
        }
    }
}

impl Error for ConsensusError {}

impl From<CanonicalEncodingError> for ConsensusError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<HashingError> for ConsensusError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

impl From<CryptoError> for ConsensusError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<ValidatorSetError> for ConsensusError {
    fn from(value: ValidatorSetError) -> Self {
        Self::ValidatorSet(value)
    }
}

/// Adapter used to sign locally generated consensus messages.
pub trait ConsensusSigner {
    /// Returns the local validator identity.
    fn validator_id(&self) -> ValidatorId;
    /// Returns the local signature scheme.
    fn signature_scheme(&self) -> SignatureSchemeId;
    /// Signs already domain-framed bytes.
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String>;
}

/// Adapter used to verify signatures from validator-set members.
pub trait ConsensusVerifier {
    /// Verifies already domain-framed bytes for a validator.
    fn verify_framed(
        &self,
        validator: ValidatorId,
        scheme: SignatureSchemeId,
        public_key: &[u8],
        framed: &[u8],
        signature: &[u8],
    ) -> Result<bool, String>;
}

/// A validator vote over one proposal digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusVote {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol replay boundary.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary.
    pub epoch: Epoch,
    /// Consensus view.
    pub view: u64,
    /// Block height.
    pub height: u64,
    /// Canonical proposal digest.
    pub proposal_digest: Digest32,
    /// Voting validator.
    pub validator: ValidatorId,
    /// Signature scheme selected by the validator set.
    pub signature_scheme: SignatureSchemeId,
    /// Signature over the domain-framed vote payload.
    pub signature: Vec<u8>,
}

/// A greater-than-two-thirds certificate for one proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCertificate {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol replay boundary.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary.
    pub epoch: Epoch,
    /// Certified view, zero only for the configured genesis anchor.
    pub view: u64,
    /// Certified height, zero only for genesis.
    pub height: u64,
    /// Certified proposal digest or configured genesis block digest.
    pub proposal_digest: Digest32,
    /// Canonically sorted validator votes. Genesis has no votes.
    pub votes: Vec<ConsensusVote>,
}

impl QuorumCertificate {
    fn genesis(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        genesis_block: Digest32,
    ) -> Self {
        Self {
            chain_id,
            protocol_version,
            epoch,
            view: 0,
            height: 0,
            proposal_digest: genesis_block,
            votes: Vec::new(),
        }
    }
}

/// A leader proposal extending a certified parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusProposal {
    /// Chain replay boundary.
    pub chain_id: ChainId,
    /// Protocol replay boundary.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary.
    pub epoch: Epoch,
    /// Consensus view.
    pub view: u64,
    /// Block height.
    pub height: u64,
    /// Deterministically selected leader.
    pub leader: ValidatorId,
    /// Certificate for the direct parent block.
    pub justify: QuorumCertificate,
    /// Ordered shared-object transaction digests.
    pub transactions: Vec<Digest32>,
    /// Leader signature scheme.
    pub signature_scheme: SignatureSchemeId,
    /// Leader signature over the proposal payload.
    pub signature: Vec<u8>,
}

/// One externally delivered consensus event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusEvent {
    /// A leader proposal arrived through an untrusted relay.
    Proposal(ConsensusProposal),
    /// A validator vote arrived through an untrusted relay.
    Vote(ConsensusVote),
    /// A quorum certificate arrived through an untrusted relay.
    Certificate(QuorumCertificate),
    /// An untrusted scheduler delivered a time observation.
    Tick { now_unix_millis: u64 },
}

/// Consensus messages that may be transported by any untrusted relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusMessage {
    /// Leader proposal.
    Proposal(ConsensusProposal),
    /// Validator vote.
    Vote(ConsensusVote),
    /// Quorum certificate.
    Certificate(QuorumCertificate),
}

/// A newly committed ordered shared-object block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedBlock {
    /// Committed height.
    pub height: u64,
    /// Committed view.
    pub view: u64,
    /// Proposal digest.
    pub digest: Digest32,
    /// Ordered transaction digests.
    pub transactions: Vec<Digest32>,
}

/// Persisted state required across otherwise stateless invocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusState {
    /// View currently eligible for proposal processing.
    pub current_view: u64,
    /// Earliest accepted tick time for a local view advance.
    pub view_deadline_unix_millis: u64,
    /// Highest proposal view voted by this validator.
    pub last_voted_view: u64,
    /// Proposal digest voted in `last_voted_view`.
    pub last_voted_digest: Option<Digest32>,
    /// Highest known quorum certificate.
    pub high_qc: QuorumCertificate,
    /// Certificate used by the HotStuff safety lock.
    pub locked_qc: QuorumCertificate,
    /// Highest committed height.
    pub committed_height: u64,
    known_proposals: BTreeMap<Digest32, ConsensusProposal>,
    certificates: BTreeMap<Digest32, QuorumCertificate>,
    pending_votes: BTreeMap<Digest32, BTreeMap<ValidatorId, ConsensusVote>>,
    observed_votes: BTreeMap<(ValidatorId, u64), Digest32>,
    committed: BTreeSet<Digest32>,
}

/// Result of one deterministic consensus transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusOutput {
    /// State to persist atomically for the next invocation.
    pub state: ConsensusState,
    /// Messages safe to hand to an untrusted transport.
    pub outbound_messages: Vec<ConsensusMessage>,
    /// Blocks newly committed by this transition.
    pub committed_blocks: Vec<CommittedBlock>,
    /// Whether a validated tick advanced the local view.
    pub view_advanced: bool,
}

/// Shared-object consensus state-machine interface.
pub trait ConsensusEngine {
    /// Returns the selected protocol identifier.
    fn protocol_id(&self) -> ConsensusProtocolId;

    /// Applies exactly one event to explicit persisted state.
    fn on_event<S: ConsensusSigner, V: ConsensusVerifier>(
        &self,
        state: &ConsensusState,
        event: ConsensusEvent,
        signer: &S,
        verifier: &V,
    ) -> Result<ConsensusOutput, ConsensusError>;
}

/// Canonical event-driven chained-HotStuff implementation.
#[derive(Clone, Debug)]
pub struct ChainedHotStuff {
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set: ValidatorSet,
    parameters: ConsensusParameters,
    resolver: HashSuiteResolver,
    genesis_block: Digest32,
}

impl ChainedHotStuff {
    /// Creates and validates a consensus instance for one epoch snapshot.
    pub fn new(
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set: ValidatorSet,
        parameters: ConsensusParameters,
        resolver: HashSuiteResolver,
        genesis_block: Digest32,
    ) -> Result<Self, ConsensusError> {
        parameters.validate()?;
        if validator_set.epoch() != epoch {
            return Err(ConsensusError::ValidatorSetEpochMismatch {
                expected: epoch,
                actual: validator_set.epoch(),
            });
        }
        if resolver.chain_id() != &chain_id {
            return Err(ConsensusError::HashChainMismatch);
        }
        if resolver.protocol_version() != protocol_version {
            return Err(ConsensusError::HashProtocolVersionMismatch);
        }
        // Resolve now so a missing active suite fails before any state is created.
        let _ = resolver.suite_for_epoch(epoch)?;
        Ok(Self {
            chain_id,
            protocol_version,
            epoch,
            validator_set,
            parameters,
            resolver,
            genesis_block,
        })
    }

    /// Returns the deterministic genesis state to persist before view 1.
    #[must_use]
    pub fn genesis_state(&self, now_unix_millis: u64) -> ConsensusState {
        let genesis_qc = QuorumCertificate::genesis(
            self.chain_id.clone(),
            self.protocol_version,
            self.epoch,
            self.genesis_block,
        );
        ConsensusState {
            current_view: 1,
            view_deadline_unix_millis: now_unix_millis
                .saturating_add(self.parameters.view_timeout_millis),
            last_voted_view: 0,
            last_voted_digest: None,
            high_qc: genesis_qc.clone(),
            locked_qc: genesis_qc,
            committed_height: 0,
            known_proposals: BTreeMap::new(),
            certificates: BTreeMap::new(),
            pending_votes: BTreeMap::new(),
            observed_votes: BTreeMap::new(),
            committed: BTreeSet::new(),
        }
    }

    /// Builds and signs a proposal when the caller is the current leader.
    pub fn propose<S: ConsensusSigner>(
        &self,
        state: &ConsensusState,
        transactions: Vec<Digest32>,
        signer: &S,
    ) -> Result<ConsensusProposal, ConsensusError> {
        self.ensure_transaction_bound(transactions.len())?;
        let expected = self
            .validator_set
            .leader(state.current_view)
            .ok_or(ConsensusError::ZeroViewOrHeight)?;
        if signer.validator_id() != expected {
            return Err(ConsensusError::InvalidLeader {
                view: state.current_view,
                expected,
                actual: signer.validator_id(),
            });
        }
        self.ensure_registered_scheme(signer.validator_id(), signer.signature_scheme())?;
        let height = state
            .high_qc
            .height
            .checked_add(1)
            .ok_or(ConsensusError::ArithmeticOverflow)?;
        let mut proposal = ConsensusProposal {
            chain_id: self.chain_id.clone(),
            protocol_version: self.protocol_version,
            epoch: self.epoch,
            view: state.current_view,
            height,
            leader: signer.validator_id(),
            justify: state.high_qc.clone(),
            transactions,
            signature_scheme: signer.signature_scheme(),
            signature: Vec::new(),
        };
        let framed = self.signature_frame(
            PROPOSAL_MESSAGE_TYPE,
            proposal.signature_scheme,
            &encode_proposal_payload(&proposal)?,
        )?;
        proposal.signature = signer
            .sign_framed(&framed)
            .map_err(ConsensusError::Authenticator)?;
        validate_signature_length(&proposal.signature)?;
        Ok(proposal)
    }

    /// Returns the active validator set.
    #[must_use]
    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    fn process_proposal<S: ConsensusSigner, V: ConsensusVerifier>(
        &self,
        state: &mut ConsensusState,
        proposal: ConsensusProposal,
        signer: &S,
        verifier: &V,
        outbound: &mut Vec<ConsensusMessage>,
        committed: &mut Vec<CommittedBlock>,
    ) -> Result<(), ConsensusError> {
        self.validate_proposal(&proposal, verifier)?;
        let digest = self.proposal_digest(&proposal)?;

        if let Some(certificate) = state.certificates.get(&digest).cloned() {
            state.known_proposals.insert(digest, proposal.clone());
            self.apply_certificate(state, proposal.justify, verifier, committed)?;
            self.apply_certificate(state, certificate, verifier, committed)?;
            return Ok(());
        }

        if proposal.view <= state.last_voted_view {
            if state.last_voted_view == proposal.view && state.last_voted_digest == Some(digest) {
                return Ok(());
            }
            return Err(ConsensusError::AlreadyVoted {
                view: proposal.view,
                previous: state
                    .last_voted_digest
                    .unwrap_or(state.locked_qc.proposal_digest),
                conflicting: digest,
            });
        }
        if proposal.view < state.current_view {
            return Err(ConsensusError::StaleProposal {
                current: state.current_view,
                received: proposal.view,
            });
        }
        self.ensure_bounded_future_view(state.current_view, proposal.view)?;
        if !self.safe_to_vote(state, &proposal) {
            return Err(ConsensusError::UnsafeProposal);
        }
        self.ensure_registered_scheme(signer.validator_id(), signer.signature_scheme())?;

        state.known_proposals.insert(digest, proposal.clone());
        self.apply_certificate(state, proposal.justify.clone(), verifier, committed)?;

        let mut vote = ConsensusVote {
            chain_id: self.chain_id.clone(),
            protocol_version: self.protocol_version,
            epoch: self.epoch,
            view: proposal.view,
            height: proposal.height,
            proposal_digest: digest,
            validator: signer.validator_id(),
            signature_scheme: signer.signature_scheme(),
            signature: Vec::new(),
        };
        let framed = self.signature_frame(
            VOTE_MESSAGE_TYPE,
            vote.signature_scheme,
            &encode_vote_payload(&vote)?,
        )?;
        vote.signature = signer
            .sign_framed(&framed)
            .map_err(ConsensusError::Authenticator)?;
        validate_signature_length(&vote.signature)?;
        state.last_voted_view = proposal.view;
        state.last_voted_digest = Some(digest);
        state.current_view = state.current_view.max(
            proposal
                .view
                .checked_add(1)
                .ok_or(ConsensusError::ArithmeticOverflow)?,
        );
        outbound.push(ConsensusMessage::Vote(vote));

        if let Some(qc) = self.try_form_certificate(state, digest)? {
            self.apply_certificate(state, qc.clone(), verifier, committed)?;
            outbound.push(ConsensusMessage::Certificate(qc));
        }
        Ok(())
    }

    fn process_vote<V: ConsensusVerifier>(
        &self,
        state: &mut ConsensusState,
        vote: ConsensusVote,
        verifier: &V,
        outbound: &mut Vec<ConsensusMessage>,
        committed: &mut Vec<CommittedBlock>,
    ) -> Result<(), ConsensusError> {
        self.validate_vote(&vote, verifier)?;
        self.ensure_bounded_future_view(state.current_view, vote.view)?;
        let key = (vote.validator, vote.view);
        if let Some(first) = state.observed_votes.get(&key) {
            if *first != vote.proposal_digest {
                return Err(ConsensusError::Equivocation {
                    validator: vote.validator,
                    view: vote.view,
                    first: *first,
                    second: vote.proposal_digest,
                });
            }
        } else {
            state.observed_votes.insert(key, vote.proposal_digest);
        }

        let votes = state.pending_votes.entry(vote.proposal_digest).or_default();
        if votes.contains_key(&vote.validator) {
            return Ok(());
        }
        let digest = vote.proposal_digest;
        votes.insert(vote.validator, vote);
        if let Some(qc) = self.try_form_certificate(state, digest)? {
            self.apply_certificate(state, qc.clone(), verifier, committed)?;
            outbound.push(ConsensusMessage::Certificate(qc));
        }
        Ok(())
    }

    fn validate_proposal<V: ConsensusVerifier>(
        &self,
        proposal: &ConsensusProposal,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.ensure_context(
            &proposal.chain_id,
            proposal.protocol_version,
            proposal.epoch,
        )?;
        if proposal.view == 0 || proposal.height == 0 {
            return Err(ConsensusError::ZeroViewOrHeight);
        }
        self.ensure_transaction_bound(proposal.transactions.len())?;
        let expected = self
            .validator_set
            .leader(proposal.view)
            .ok_or(ConsensusError::ZeroViewOrHeight)?;
        if proposal.leader != expected {
            return Err(ConsensusError::InvalidLeader {
                view: proposal.view,
                expected,
                actual: proposal.leader,
            });
        }
        if proposal.height
            != proposal
                .justify
                .height
                .checked_add(1)
                .ok_or(ConsensusError::ArithmeticOverflow)?
        {
            return Err(ConsensusError::InvalidProposalHeight);
        }
        if proposal.view <= proposal.justify.view {
            return Err(ConsensusError::InvalidProposalView);
        }
        self.verify_certificate(&proposal.justify, verifier)?;
        self.ensure_registered_scheme(proposal.leader, proposal.signature_scheme)?;
        validate_signature_length(&proposal.signature)?;
        let info = self
            .validator_set
            .get(proposal.leader)
            .ok_or(ConsensusError::UnknownValidator(proposal.leader))?;
        let framed = self.signature_frame(
            PROPOSAL_MESSAGE_TYPE,
            proposal.signature_scheme,
            &encode_proposal_payload(proposal)?,
        )?;
        let valid = verifier
            .verify_framed(
                proposal.leader,
                proposal.signature_scheme,
                &info.public_key,
                &framed,
                &proposal.signature,
            )
            .map_err(ConsensusError::Authenticator)?;
        if !valid {
            return Err(ConsensusError::InvalidSignature(proposal.leader));
        }
        Ok(())
    }

    fn validate_vote<V: ConsensusVerifier>(
        &self,
        vote: &ConsensusVote,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.ensure_context(&vote.chain_id, vote.protocol_version, vote.epoch)?;
        if vote.view == 0 || vote.height == 0 {
            return Err(ConsensusError::ZeroViewOrHeight);
        }
        self.ensure_registered_scheme(vote.validator, vote.signature_scheme)?;
        validate_signature_length(&vote.signature)?;
        let info = self
            .validator_set
            .get(vote.validator)
            .ok_or(ConsensusError::UnknownValidator(vote.validator))?;
        let framed = self.signature_frame(
            VOTE_MESSAGE_TYPE,
            vote.signature_scheme,
            &encode_vote_payload(vote)?,
        )?;
        let valid = verifier
            .verify_framed(
                vote.validator,
                vote.signature_scheme,
                &info.public_key,
                &framed,
                &vote.signature,
            )
            .map_err(ConsensusError::Authenticator)?;
        if !valid {
            return Err(ConsensusError::InvalidSignature(vote.validator));
        }
        Ok(())
    }

    fn verify_certificate<V: ConsensusVerifier>(
        &self,
        certificate: &QuorumCertificate,
        verifier: &V,
    ) -> Result<(), ConsensusError> {
        self.ensure_context(
            &certificate.chain_id,
            certificate.protocol_version,
            certificate.epoch,
        )?;
        if certificate.view == 0 || certificate.height == 0 {
            if certificate.view == 0
                && certificate.height == 0
                && certificate.proposal_digest == self.genesis_block
                && certificate.votes.is_empty()
            {
                return Ok(());
            }
            return Err(ConsensusError::InvalidGenesisCertificate);
        }
        let mut previous = None;
        let mut power = 0u64;
        for vote in &certificate.votes {
            if previous.is_some_and(|id| id >= vote.validator) {
                return Err(ConsensusError::NonCanonicalCertificateVotes);
            }
            previous = Some(vote.validator);
            if vote.view != certificate.view
                || vote.height != certificate.height
                || vote.proposal_digest != certificate.proposal_digest
            {
                return Err(ConsensusError::CertificateVoteMismatch);
            }
            self.validate_vote(vote, verifier)?;
            let validator = self
                .validator_set
                .get(vote.validator)
                .ok_or(ConsensusError::UnknownValidator(vote.validator))?;
            power = power
                .checked_add(validator.voting_power)
                .ok_or(ConsensusError::ArithmeticOverflow)?;
        }
        let required = self.validator_set.quorum_threshold();
        if power < required {
            return Err(ConsensusError::InsufficientQuorum {
                actual: power,
                required,
            });
        }
        Ok(())
    }

    fn try_form_certificate(
        &self,
        state: &ConsensusState,
        digest: Digest32,
    ) -> Result<Option<QuorumCertificate>, ConsensusError> {
        if state.certificates.contains_key(&digest) {
            return Ok(None);
        }
        let Some(proposal) = state.known_proposals.get(&digest) else {
            return Ok(None);
        };
        let Some(pending) = state.pending_votes.get(&digest) else {
            return Ok(None);
        };
        let mut power = 0u64;
        let mut matching = Vec::new();
        for vote in pending.values() {
            if vote.view != proposal.view || vote.height != proposal.height {
                continue;
            }
            let validator = self
                .validator_set
                .get(vote.validator)
                .ok_or(ConsensusError::UnknownValidator(vote.validator))?;
            power = power
                .checked_add(validator.voting_power)
                .ok_or(ConsensusError::ArithmeticOverflow)?;
            matching.push(vote.clone());
        }
        if power < self.validator_set.quorum_threshold() {
            return Ok(None);
        }
        Ok(Some(QuorumCertificate {
            chain_id: self.chain_id.clone(),
            protocol_version: self.protocol_version,
            epoch: self.epoch,
            view: proposal.view,
            height: proposal.height,
            proposal_digest: digest,
            votes: matching,
        }))
    }

    fn apply_certificate<V: ConsensusVerifier>(
        &self,
        state: &mut ConsensusState,
        certificate: QuorumCertificate,
        verifier: &V,
        committed: &mut Vec<CommittedBlock>,
    ) -> Result<(), ConsensusError> {
        self.verify_certificate(&certificate, verifier)?;
        if certificate.view == 0 {
            return Ok(());
        }
        state
            .certificates
            .entry(certificate.proposal_digest)
            .or_insert_with(|| certificate.clone());
        if certificate.view > state.high_qc.view {
            state.high_qc = certificate.clone();
        }
        state.current_view = state.current_view.max(
            certificate
                .view
                .checked_add(1)
                .ok_or(ConsensusError::ArithmeticOverflow)?,
        );

        let Some(block) = state
            .known_proposals
            .get(&certificate.proposal_digest)
            .cloned()
        else {
            return Ok(());
        };
        if block.view != certificate.view || block.height != certificate.height {
            return Err(ConsensusError::CertificateProposalMismatch);
        }
        if block.justify.view > state.locked_qc.view {
            state.locked_qc = block.justify.clone();
        }
        let Some(parent) = state
            .known_proposals
            .get(&block.justify.proposal_digest)
            .cloned()
        else {
            return Ok(());
        };
        if parent.height.checked_add(1) != Some(block.height)
            || parent.justify.height.checked_add(1) != Some(parent.height)
        {
            return Ok(());
        }
        self.commit_through(state, parent.justify.proposal_digest, committed)
    }

    fn commit_through(
        &self,
        state: &mut ConsensusState,
        target: Digest32,
        committed: &mut Vec<CommittedBlock>,
    ) -> Result<(), ConsensusError> {
        let mut chain = Vec::new();
        let mut cursor = target;
        while let Some(proposal) = state.known_proposals.get(&cursor) {
            if proposal.height <= state.committed_height {
                break;
            }
            chain.push((cursor, proposal.clone()));
            cursor = proposal.justify.proposal_digest;
        }
        chain.reverse();
        for (digest, proposal) in chain {
            if proposal.height
                != state
                    .committed_height
                    .checked_add(1)
                    .ok_or(ConsensusError::ArithmeticOverflow)?
            {
                return Ok(());
            }
            if state.committed.insert(digest) {
                state.committed_height = proposal.height;
                committed.push(CommittedBlock {
                    height: proposal.height,
                    view: proposal.view,
                    digest,
                    transactions: proposal.transactions,
                });
            }
        }
        Ok(())
    }

    fn safe_to_vote(&self, state: &ConsensusState, proposal: &ConsensusProposal) -> bool {
        proposal.justify.view > state.locked_qc.view
            || self.extends(
                state,
                proposal.justify.proposal_digest,
                state.locked_qc.proposal_digest,
            )
    }

    fn extends(&self, state: &ConsensusState, mut candidate: Digest32, ancestor: Digest32) -> bool {
        loop {
            if candidate == ancestor {
                return true;
            }
            let Some(proposal) = state.known_proposals.get(&candidate) else {
                return false;
            };
            if proposal.height == 0 {
                return false;
            }
            candidate = proposal.justify.proposal_digest;
        }
    }

    /// Hashes a complete signed proposal in the consensus-message domain.
    pub fn proposal_digest(
        &self,
        proposal: &ConsensusProposal,
    ) -> Result<Digest32, ConsensusError> {
        Ok(self.resolver.hash_for_purpose(
            self.epoch,
            HashPurpose::ConsensusMessage,
            &encode_proposal(proposal)?,
        )?)
    }

    fn ensure_context(
        &self,
        chain_id: &ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
    ) -> Result<(), ConsensusError> {
        if chain_id != &self.chain_id
            || protocol_version != self.protocol_version
            || epoch != self.epoch
        {
            return Err(ConsensusError::ContextMismatch);
        }
        Ok(())
    }

    fn ensure_transaction_bound(&self, count: usize) -> Result<(), ConsensusError> {
        if count
            > usize::try_from(self.parameters.max_block_transactions)
                .map_err(|_| ConsensusError::ArithmeticOverflow)?
        {
            return Err(ConsensusError::TooManyTransactions(count));
        }
        Ok(())
    }

    fn ensure_bounded_future_view(
        &self,
        current: u64,
        received: u64,
    ) -> Result<(), ConsensusError> {
        let maximum = current.saturating_add(MAX_FUTURE_VIEW_GAP);
        if received > maximum {
            return Err(ConsensusError::FutureView { current, received });
        }
        Ok(())
    }

    fn ensure_registered_scheme(
        &self,
        validator: ValidatorId,
        scheme: SignatureSchemeId,
    ) -> Result<(), ConsensusError> {
        let info = self
            .validator_set
            .get(validator)
            .ok_or(ConsensusError::UnknownValidator(validator))?;
        if info.signature_scheme != scheme {
            return Err(ConsensusError::SignatureSchemeMismatch(validator));
        }
        Ok(())
    }

    fn prune_state(&self, state: &mut ConsensusState) {
        let minimum_height = state
            .committed_height
            .saturating_sub(RETAIN_COMMITTED_HEIGHTS);
        let high = state.high_qc.proposal_digest;
        let locked = state.locked_qc.proposal_digest;
        state.known_proposals.retain(|digest, proposal| {
            proposal.height >= minimum_height || *digest == high || *digest == locked
        });
        state.certificates.retain(|digest, certificate| {
            certificate.height >= minimum_height || *digest == high || *digest == locked
        });
        state.pending_votes.retain(|digest, votes| {
            if state.certificates.contains_key(digest) {
                return false;
            }
            votes.values().next().is_some_and(|vote| {
                vote.view.saturating_add(MAX_FUTURE_VIEW_GAP) >= state.current_view
            })
        });
        state
            .observed_votes
            .retain(|(_, view), _| view.saturating_add(MAX_FUTURE_VIEW_GAP) >= state.current_view);
        state
            .committed
            .retain(|digest| state.known_proposals.contains_key(digest));
    }

    fn signature_frame(
        &self,
        message_type: &str,
        signature_scheme_id: SignatureSchemeId,
        payload: &[u8],
    ) -> Result<Vec<u8>, ConsensusError> {
        Ok(frame_signature_message(
            &SignatureDomain {
                chain_id: self.chain_id.clone(),
                protocol_version: self.protocol_version,
                epoch: self.epoch,
                message_type: SignatureMessageType::new(message_type)?,
                signature_scheme_id,
            },
            payload,
        )?)
    }
}

impl ConsensusEngine for ChainedHotStuff {
    fn protocol_id(&self) -> ConsensusProtocolId {
        self.parameters.protocol
    }

    fn on_event<S: ConsensusSigner, V: ConsensusVerifier>(
        &self,
        state: &ConsensusState,
        event: ConsensusEvent,
        signer: &S,
        verifier: &V,
    ) -> Result<ConsensusOutput, ConsensusError> {
        self.ensure_registered_scheme(signer.validator_id(), signer.signature_scheme())?;
        let mut next = state.clone();
        let mut outbound = Vec::new();
        let mut committed = Vec::new();
        let mut view_advanced = false;
        match event {
            ConsensusEvent::Proposal(proposal) => self.process_proposal(
                &mut next,
                proposal,
                signer,
                verifier,
                &mut outbound,
                &mut committed,
            )?,
            ConsensusEvent::Vote(vote) => {
                self.process_vote(&mut next, vote, verifier, &mut outbound, &mut committed)?
            }
            ConsensusEvent::Certificate(certificate) => {
                self.apply_certificate(&mut next, certificate, verifier, &mut committed)?;
            }
            ConsensusEvent::Tick { now_unix_millis } => {
                if now_unix_millis >= next.view_deadline_unix_millis {
                    next.current_view = next
                        .current_view
                        .checked_add(1)
                        .ok_or(ConsensusError::ArithmeticOverflow)?;
                    next.view_deadline_unix_millis = now_unix_millis
                        .checked_add(self.parameters.view_timeout_millis)
                        .ok_or(ConsensusError::ArithmeticOverflow)?;
                    view_advanced = true;
                }
            }
        }
        self.prune_state(&mut next);
        Ok(ConsensusOutput {
            state: next,
            outbound_messages: outbound,
            committed_blocks: committed,
            view_advanced,
        })
    }
}

fn validate_signature_length(signature: &[u8]) -> Result<(), ConsensusError> {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(ConsensusError::InvalidSignatureLength(signature.len()));
    }
    Ok(())
}

/// Encodes consensus parameters for inclusion in `ProtocolConfig`.
pub fn encode_consensus_parameters(
    parameters: ConsensusParameters,
) -> Result<Vec<u8>, ConsensusError> {
    parameters.validate()?;
    let mut canonical = CanonicalStruct::new(PARAMETERS_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, parameters.protocol.as_u16())?;
    canonical.field_u32(2, parameters.max_block_transactions)?;
    canonical.field_u64(3, parameters.view_timeout_millis)?;
    Ok(canonical.finish()?)
}

/// Encodes the leader-signable proposal payload without its signature.
pub fn encode_proposal_payload(proposal: &ConsensusProposal) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical = CanonicalStruct::new(PROPOSAL_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, proposal.chain_id.as_str())?;
    canonical.field_u32(2, proposal.protocol_version.get())?;
    canonical.field_u64(3, proposal.epoch.get())?;
    canonical.field_u64(4, proposal.view)?;
    canonical.field_u64(5, proposal.height)?;
    canonical.field_bytes(6, proposal.leader.as_bytes())?;
    canonical.field_bytes(7, encode_quorum_certificate(&proposal.justify)?)?;
    canonical.field_u32(
        8,
        u32::try_from(proposal.transactions.len())
            .map_err(|_| ConsensusError::TooManyTransactions(proposal.transactions.len()))?,
    )?;
    for (index, transaction) in proposal.transactions.iter().enumerate() {
        let field = u16::try_from(index + 10)
            .map_err(|_| ConsensusError::TooManyTransactions(proposal.transactions.len()))?;
        canonical.field_bytes(field, encode_digest32(transaction)?)?;
    }
    canonical.field_u16(9, proposal.signature_scheme.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes a complete proposal including its leader signature.
pub fn encode_proposal(proposal: &ConsensusProposal) -> Result<Vec<u8>, ConsensusError> {
    validate_signature_length(&proposal.signature)?;
    let mut canonical = CanonicalStruct::new(PROPOSAL_TYPE_ID, ENCODING_VERSION + 1);
    canonical.field_bytes(1, encode_proposal_payload(proposal)?)?;
    canonical.field_bytes(2, proposal.signature.clone())?;
    Ok(canonical.finish()?)
}

/// Encodes the signable vote payload without its signature.
pub fn encode_vote_payload(vote: &ConsensusVote) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical = CanonicalStruct::new(VOTE_PAYLOAD_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, vote.chain_id.as_str())?;
    canonical.field_u32(2, vote.protocol_version.get())?;
    canonical.field_u64(3, vote.epoch.get())?;
    canonical.field_u64(4, vote.view)?;
    canonical.field_u64(5, vote.height)?;
    canonical.field_bytes(6, encode_digest32(&vote.proposal_digest)?)?;
    canonical.field_bytes(7, vote.validator.as_bytes())?;
    canonical.field_u16(8, vote.signature_scheme.as_u16())?;
    Ok(canonical.finish()?)
}

/// Encodes a complete consensus vote.
pub fn encode_vote(vote: &ConsensusVote) -> Result<Vec<u8>, ConsensusError> {
    validate_signature_length(&vote.signature)?;
    let mut canonical = CanonicalStruct::new(VOTE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_vote_payload(vote)?)?;
    canonical.field_bytes(2, vote.signature.clone())?;
    Ok(canonical.finish()?)
}

/// Encodes a quorum certificate with canonically ordered votes.
pub fn encode_quorum_certificate(
    certificate: &QuorumCertificate,
) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical = CanonicalStruct::new(CERTIFICATE_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, certificate.chain_id.as_str())?;
    canonical.field_u32(2, certificate.protocol_version.get())?;
    canonical.field_u64(3, certificate.epoch.get())?;
    canonical.field_u64(4, certificate.view)?;
    canonical.field_u64(5, certificate.height)?;
    canonical.field_bytes(6, encode_digest32(&certificate.proposal_digest)?)?;
    canonical.field_u32(
        7,
        u32::try_from(certificate.votes.len())
            .map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?,
    )?;
    for (index, vote) in certificate.votes.iter().enumerate() {
        let field =
            u16::try_from(index + 8).map_err(|_| ConsensusError::NonCanonicalCertificateVotes)?;
        canonical.field_bytes(field, encode_vote(vote)?)?;
    }
    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{HashAlgorithmId, HashSuite, HashSuiteSchedule};
    use sha2::{Digest as _, Sha256};
    use validator_set::ValidatorInfo;

    #[derive(Clone)]
    struct TestCrypto {
        validator: ValidatorId,
    }

    impl TestCrypto {
        fn signature(validator: ValidatorId, framed: &[u8]) -> Vec<u8> {
            let mut hasher = Sha256::new();
            hasher.update(validator.as_bytes());
            hasher.update(framed);
            hasher.finalize().to_vec()
        }
    }

    impl ConsensusSigner for TestCrypto {
        fn validator_id(&self) -> ValidatorId {
            self.validator
        }

        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }

        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            Ok(Self::signature(self.validator, framed))
        }
    }

    impl ConsensusVerifier for TestCrypto {
        fn verify_framed(
            &self,
            validator: ValidatorId,
            _scheme: SignatureSchemeId,
            public_key: &[u8],
            framed: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            Ok(public_key == validator.as_bytes()
                && signature == Self::signature(validator, framed))
        }
    }

    fn validator(byte: u8) -> ValidatorInfo {
        ValidatorInfo {
            id: ValidatorId::new([byte; 32]),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: vec![byte; 32],
        }
    }

    fn setup() -> (ChainedHotStuff, Vec<TestCrypto>) {
        let chain = ChainId::new("sunrise-consensus-test").unwrap();
        let version = ProtocolVersion::new(1);
        let epoch = Epoch::new(8);
        let validators = (1..=4).map(validator).collect::<Vec<_>>();
        let set = ValidatorSet::new(epoch, validators).unwrap();
        let resolver = HashSuiteResolver::new(
            chain.clone(),
            version,
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let engine = ChainedHotStuff::new(
            chain,
            version,
            epoch,
            set,
            ConsensusParameters::genesis(),
            resolver,
            Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]),
        )
        .unwrap();
        let cryptos = (1..=4)
            .map(|byte| TestCrypto {
                validator: ValidatorId::new([byte; 32]),
            })
            .collect();
        (engine, cryptos)
    }

    fn proposal_votes(
        engine: &ChainedHotStuff,
        states: &mut [ConsensusState],
        cryptos: &[TestCrypto],
        transaction_byte: u8,
    ) -> (ConsensusProposal, Vec<ConsensusVote>) {
        let view = states[0].current_view;
        let leader = engine.validator_set().leader(view).unwrap();
        let leader_index = cryptos
            .iter()
            .position(|crypto| crypto.validator == leader)
            .unwrap();
        let proposal = engine
            .propose(
                &states[leader_index],
                vec![Digest32::new(
                    HashAlgorithmId::Sha2_256,
                    [transaction_byte; 32],
                )],
                &cryptos[leader_index],
            )
            .unwrap();
        let mut votes = Vec::new();
        for (index, crypto) in cryptos.iter().enumerate() {
            let output = engine
                .on_event(
                    &states[index],
                    ConsensusEvent::Proposal(proposal.clone()),
                    crypto,
                    crypto,
                )
                .unwrap();
            states[index] = output.state;
            let ConsensusMessage::Vote(vote) = output.outbound_messages[0].clone() else {
                panic!("proposal must emit a vote")
            };
            votes.push(vote);
        }
        (proposal, votes)
    }

    fn certify(
        engine: &ChainedHotStuff,
        states: &mut [ConsensusState],
        cryptos: &[TestCrypto],
        votes: &[ConsensusVote],
    ) -> (QuorumCertificate, Vec<CommittedBlock>) {
        let mut aggregator = states[0].clone();
        let mut certificate = None;
        for vote in votes.iter().take(3).rev() {
            let output = engine
                .on_event(
                    &aggregator,
                    ConsensusEvent::Vote(vote.clone()),
                    &cryptos[0],
                    &cryptos[0],
                )
                .unwrap();
            aggregator = output.state;
            certificate = output
                .outbound_messages
                .into_iter()
                .find_map(|message| {
                    if let ConsensusMessage::Certificate(qc) = message {
                        Some(qc)
                    } else {
                        None
                    }
                })
                .or(certificate);
        }
        let certificate = certificate.expect("three of four votes must certify");
        let mut committed = Vec::new();
        for (index, crypto) in cryptos.iter().enumerate() {
            let output = engine
                .on_event(
                    &states[index],
                    ConsensusEvent::Certificate(certificate.clone()),
                    crypto,
                    crypto,
                )
                .unwrap();
            states[index] = output.state;
            committed.extend(output.committed_blocks);
        }
        (certificate, committed)
    }

    #[test]
    fn four_validators_commit_identical_order_after_three_chain() {
        let (engine, cryptos) = setup();
        let mut states = vec![engine.genesis_state(0); 4];
        let mut first_digest = None;
        let mut final_commits = Vec::new();

        for byte in 1..=3 {
            let (proposal, votes) = proposal_votes(&engine, &mut states, &cryptos, byte);
            if first_digest.is_none() {
                first_digest = Some(engine.proposal_digest(&proposal).unwrap());
            }
            let (_, commits) = certify(&engine, &mut states, &cryptos, &votes);
            final_commits.extend(commits);
        }

        assert_eq!(
            states
                .iter()
                .map(|state| state.committed_height)
                .collect::<Vec<_>>(),
            vec![1; 4]
        );
        assert!(
            final_commits
                .iter()
                .all(|block| block.digest == first_digest.unwrap())
        );
        assert_eq!(final_commits.len(), 4);
    }

    #[test]
    fn vote_arrival_order_produces_identical_certificate_bytes() {
        let (engine, cryptos) = setup();
        let mut states = vec![engine.genesis_state(0); 4];
        let (_, votes) = proposal_votes(&engine, &mut states, &cryptos, 9);
        let base = states[0].clone();

        let aggregate = |order: &[usize]| {
            let mut state = base.clone();
            let mut certificate = None;
            for index in order {
                let output = engine
                    .on_event(
                        &state,
                        ConsensusEvent::Vote(votes[*index].clone()),
                        &cryptos[0],
                        &cryptos[0],
                    )
                    .unwrap();
                state = output.state;
                certificate = output
                    .outbound_messages
                    .into_iter()
                    .find_map(|message| {
                        if let ConsensusMessage::Certificate(qc) = message {
                            Some(qc)
                        } else {
                            None
                        }
                    })
                    .or(certificate);
            }
            encode_quorum_certificate(&certificate.unwrap()).unwrap()
        };

        assert_eq!(aggregate(&[0, 1, 2]), aggregate(&[2, 0, 1]));
    }

    #[test]
    fn conflicting_proposal_cannot_receive_a_second_honest_vote() {
        let (engine, cryptos) = setup();
        let state = engine.genesis_state(0);
        let first = engine
            .propose(
                &state,
                vec![Digest32::new(HashAlgorithmId::Sha2_256, [1; 32])],
                &cryptos[0],
            )
            .unwrap();
        let second = engine
            .propose(
                &state,
                vec![Digest32::new(HashAlgorithmId::Sha2_256, [2; 32])],
                &cryptos[0],
            )
            .unwrap();
        let output = engine
            .on_event(
                &state,
                ConsensusEvent::Proposal(first),
                &cryptos[1],
                &cryptos[1],
            )
            .unwrap();
        assert!(matches!(
            engine.on_event(
                &output.state,
                ConsensusEvent::Proposal(second),
                &cryptos[1],
                &cryptos[1]
            ),
            Err(ConsensusError::AlreadyVoted { view: 1, .. })
        ));
    }

    #[test]
    fn duplicate_vote_and_certificate_delivery_is_idempotent() {
        let (engine, cryptos) = setup();
        let mut states = vec![engine.genesis_state(0); 4];
        let (_, votes) = proposal_votes(&engine, &mut states, &cryptos, 4);
        let state = states[0].clone();
        let first = engine
            .on_event(
                &state,
                ConsensusEvent::Vote(votes[0].clone()),
                &cryptos[0],
                &cryptos[0],
            )
            .unwrap();
        let duplicate = engine
            .on_event(
                &first.state,
                ConsensusEvent::Vote(votes[0].clone()),
                &cryptos[0],
                &cryptos[0],
            )
            .unwrap();
        assert_eq!(duplicate.state, first.state);
        assert!(duplicate.outbound_messages.is_empty());

        let (certificate, _) = certify(&engine, &mut states, &cryptos, &votes);
        let applied = engine
            .on_event(
                &states[0],
                ConsensusEvent::Certificate(certificate.clone()),
                &cryptos[0],
                &cryptos[0],
            )
            .unwrap();
        let replayed = engine
            .on_event(
                &applied.state,
                ConsensusEvent::Certificate(certificate),
                &cryptos[0],
                &cryptos[0],
            )
            .unwrap();
        assert_eq!(replayed.state, applied.state);
        assert!(replayed.committed_blocks.is_empty());
    }

    #[test]
    fn certificate_before_proposal_converges_to_the_same_state() {
        let (engine, cryptos) = setup();
        let mut working = vec![engine.genesis_state(0); 4];
        let (proposal, votes) = proposal_votes(&engine, &mut working, &cryptos, 7);

        let mut aggregate = working[0].clone();
        let mut certificate = None;
        for vote in votes.iter().take(3) {
            let output = engine
                .on_event(
                    &aggregate,
                    ConsensusEvent::Vote(vote.clone()),
                    &cryptos[0],
                    &cryptos[0],
                )
                .unwrap();
            aggregate = output.state;
            certificate = output
                .outbound_messages
                .into_iter()
                .find_map(|message| match message {
                    ConsensusMessage::Certificate(qc) => Some(qc),
                    _ => None,
                })
                .or(certificate);
        }
        let certificate = certificate.unwrap();

        let fresh = engine.genesis_state(0);
        let proposal_first = engine
            .on_event(
                &fresh,
                ConsensusEvent::Proposal(proposal.clone()),
                &cryptos[1],
                &cryptos[1],
            )
            .unwrap();
        let normal = engine
            .on_event(
                &proposal_first.state,
                ConsensusEvent::Certificate(certificate.clone()),
                &cryptos[1],
                &cryptos[1],
            )
            .unwrap();

        let certificate_first = engine
            .on_event(
                &fresh,
                ConsensusEvent::Certificate(certificate),
                &cryptos[1],
                &cryptos[1],
            )
            .unwrap();
        let reordered = engine
            .on_event(
                &certificate_first.state,
                ConsensusEvent::Proposal(proposal),
                &cryptos[1],
                &cryptos[1],
            )
            .unwrap();

        assert_eq!(reordered.state.high_qc, normal.state.high_qc);
        assert_eq!(reordered.state.locked_qc, normal.state.locked_qc);
        assert_eq!(reordered.state.certificates, normal.state.certificates);
        assert_eq!(
            reordered.state.known_proposals,
            normal.state.known_proposals
        );
        assert!(reordered.outbound_messages.is_empty());
    }

    #[test]
    fn stale_tick_cannot_advance_view_and_ready_tick_advances_once() {
        let (engine, cryptos) = setup();
        let state = engine.genesis_state(100);
        let early = engine
            .on_event(
                &state,
                ConsensusEvent::Tick {
                    now_unix_millis: 10_099,
                },
                &cryptos[0],
                &cryptos[0],
            )
            .unwrap();
        assert_eq!(early.state.current_view, 1);
        assert!(!early.view_advanced);

        let ready = engine
            .on_event(
                &early.state,
                ConsensusEvent::Tick {
                    now_unix_millis: 10_100,
                },
                &cryptos[0],
                &cryptos[0],
            )
            .unwrap();
        assert_eq!(ready.state.current_view, 2);
        assert!(ready.view_advanced);
    }

    #[test]
    fn wrong_epoch_vote_is_rejected_before_aggregation() {
        let (engine, cryptos) = setup();
        let mut states = vec![engine.genesis_state(0); 4];
        let (_, mut votes) = proposal_votes(&engine, &mut states, &cryptos, 1);
        votes[0].epoch = Epoch::new(99);
        assert_eq!(
            engine.on_event(
                &states[0],
                ConsensusEvent::Vote(votes.remove(0)),
                &cryptos[0],
                &cryptos[0]
            ),
            Err(ConsensusError::ContextMismatch)
        );
    }

    #[test]
    fn consensus_parameter_encoding_is_stable() {
        let bytes = encode_consensus_parameters(ConsensusParameters::genesis()).unwrap();
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            concat!(
                "534e524505d001000300",
                "0100020000000100",
                "02000400000000040000",
                "0300080000001027000000000000"
            )
        );
    }
}
