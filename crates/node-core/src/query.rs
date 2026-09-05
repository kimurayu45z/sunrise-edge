//! Public read-only query helpers for the bounded Developer MVP query API
//! (docs/architecture/decisions/0081-0087-cli-first-roadmap.md §43, DR-0082).
//!
//! Every result here is independently loaded and cross-checked by node-core;
//! the HTTP adapter must not reinterpret storage rows or reimplement these
//! checks itself. In particular, [`SenderNonceRecord`]'s private canonical
//! framing never crosses this boundary: only its decoded `u64` next-nonce
//! value does. Every result type below also carries the exact selector it
//! answers (`object_id`/`request_id`) in every status, so a caller — or an
//! HTTP adapter building a canonical response — can never accidentally bind
//! one query's result to a different selector.

use super::{
    MAX_AUTHENTICATED_OBJECT_BODY_BYTES, NodeCoreError, NodeDedupRecord, RequestId,
    SenderNonceRecord,
};
use hashing::HashingError;
use objects::{Object, ObjectId};
use protocol_types::{ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion};
use runtime::{
    AtomicityDomainId, DurableObjectHead, DurableObjectOwnerProjection, DurableObjectPayload,
    DurableObjectVersion, DurableOperationContext, DurableRequestId, ObjectHeadRevision,
    PersistenceLayout, StateRevision, StructuredDurableDomainStateStore,
};

/// One observed persisted next-nonce value plus the exact revision it was
/// read at, shared by the authenticated write path and the public query
/// helper below so their decode/corruption rules can never diverge.
pub(super) struct SenderNextNonceObservation {
    pub(super) next_nonce: u64,
    pub(super) revision: StateRevision,
}

/// Reads and strictly validates the persisted next-nonce record at
/// `nonce_key`, the shared decode path for both the authenticated submission
/// boundary and [`query_sender_next_nonce`].
///
/// True absence (never written, `StateRevision::INITIAL`) reads as `0`. A
/// missing value at any other revision means the record was deleted while
/// its epoch may still be accepted, which is persisted corruption and fails
/// closed rather than silently resetting the sender's nonce.
pub(super) fn read_sender_next_nonce<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    nonce_key: &[u8],
    sender: [u8; 32],
    epoch: Epoch,
) -> Result<SenderNextNonceObservation, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
{
    let observed = store.get_versioned_durable(context, domain, nonce_key)?;
    let next_nonce = match observed.value() {
        Some(bytes) => {
            let record = SenderNonceRecord::decode(bytes).map_err(|_| {
                NodeCoreError::PersistenceInvariant("invalid persisted sender nonce record")
            })?;
            if record.sender != sender || record.epoch != epoch {
                return Err(NodeCoreError::PersistenceInvariant(
                    "persisted sender nonce record does not match its key's sender/epoch",
                ));
            }
            record.next_nonce
        }
        None if observed.revision() == StateRevision::INITIAL => 0,
        None => {
            return Err(NodeCoreError::PersistenceInvariant(
                "persisted sender nonce record was deleted while its epoch may be accepted",
            ));
        }
    };
    Ok(SenderNextNonceObservation {
        next_nonce,
        revision: observed.revision(),
    })
}

/// Queries the persisted next nonce for `sender` at `epoch`.
///
/// True absence returns `0`; a deleted or otherwise corrupt persisted record
/// for an epoch that may still be accepted is storage corruption and fails
/// closed. `sender` is only an untrusted public lookup selector here: it
/// grants no authority, and the returned value is usable only by a
/// transaction whose own signature authenticates that same sender.
pub fn query_sender_next_nonce<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    sender: [u8; 32],
) -> Result<u64, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
{
    let layout = PersistenceLayout::new(chain_id, protocol_version);
    let nonce_key = layout.sender_nonce_key(sender, epoch);
    let observation = read_sender_next_nonce(store, context, domain, &nonce_key, sender, epoch)?;
    Ok(observation.next_nonce)
}

/// Independently verified result of querying one durable object by identifier.
///
/// Absence, a retained tombstone, a verified current inline object, and a
/// current blob reference are represented explicitly and exhaustively: a
/// blob-backed version never claims to have verified an unavailable blob
/// body, it only reports its self-describing metadata and blob digest. Every
/// variant carries the exact `object_id` this result answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectQueryResult {
    /// No head row has ever existed for this object identifier.
    Absent {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
    },
    /// A delete retained the last immutable version and head revision.
    Tombstoned {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
        /// ABA-safe revision installed by the delete.
        head_revision: ObjectHeadRevision,
        /// Last immutable version reconstructed from retained history.
        last_object_version: DurableObjectVersion,
    },
    /// A current, independently verified inline object.
    CurrentInline {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
        /// ABA-safe revision installed by the latest write.
        head_revision: ObjectHeadRevision,
        /// Current immutable object version.
        object_version: DurableObjectVersion,
        /// Self-describing digest of the current object version, independently
        /// recomputed and verified against the returned canonical body.
        digest: Digest32,
        /// Exact canonical `objects::Object` bytes, digest-verified.
        canonical_object_bytes: Vec<u8>,
    },
    /// A current version whose body is stored externally as a blob.
    ///
    /// This MVP does not fetch or verify blob content: only the explicit
    /// head/version metadata and the blob's own self-describing digest are
    /// returned. Neither `digest` nor `blob_digest` is verified against
    /// fetched bytes here; both are the values recorded on the immutable
    /// version, cross-checked against the head.
    CurrentBlobReference {
        /// The exact object identifier this result answers.
        object_id: ObjectId,
        /// ABA-safe revision installed by the latest write.
        head_revision: ObjectHeadRevision,
        /// Current immutable object version.
        object_version: DurableObjectVersion,
        /// Self-describing digest of the current object version, as recorded
        /// on the immutable version and cross-checked against the head. Not
        /// body-verified: the referenced body is never fetched.
        digest: Digest32,
        /// Self-describing digest of the externally stored blob content, as
        /// recorded on the immutable version. Never fetched or verified.
        blob_digest: Digest32,
    },
}

impl ObjectQueryResult {
    /// Returns the exact object identifier this result answers, regardless
    /// of status. Callers (including HTTP adapters) should use this instead
    /// of threading their own copy of the requested selector, so a result can
    /// never be silently rebound to another identifier.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        match self {
            Self::Absent { object_id }
            | Self::Tombstoned { object_id, .. }
            | Self::CurrentInline { object_id, .. }
            | Self::CurrentBlobReference { object_id, .. } => *object_id,
        }
    }
}

/// Loads and independently verifies one durable object by identifier.
///
/// This cross-checks the head, the linked immutable version record, object
/// identity, version, digest, schema, the version's stored creating
/// chain/protocol provenance, and (for an inline body) the owner projection
/// and self-describing digest — exactly the corruption-guard rules
/// `load_and_authorize_objects` applies, minus the owner-authorization step,
/// since a public query has no signed authority to authorize against. The
/// creating-chain check runs before branching on inline versus blob payload,
/// so a cross-chain blob record fails closed exactly like a cross-chain
/// inline record even though a blob body is never fetched or verified.
pub fn query_object<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain_id: &ChainId,
    object_id: ObjectId,
) -> Result<ObjectQueryResult, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
{
    let head: DurableObjectHead = store.get_object_head(context, domain, object_id)?;
    let (head_revision, object_version, digest) = match &head {
        DurableObjectHead::Absent => return Ok(ObjectQueryResult::Absent { object_id }),
        DurableObjectHead::Tombstoned {
            head_revision,
            last_object_version,
        } => {
            return Ok(ObjectQueryResult::Tombstoned {
                object_id,
                head_revision: *head_revision,
                last_object_version: *last_object_version,
            });
        }
        DurableObjectHead::Current {
            head_revision,
            object_version,
            digest,
            ..
        } => (*head_revision, *object_version, *digest),
    };

    let record = store
        .get_object_version(context, domain, object_id, object_version)?
        .ok_or(NodeCoreError::ObjectRecordMissing { object_id })?;
    if record.object_id() != object_id
        || record.object_version() != object_version
        || record.digest() != digest
    {
        return Err(NodeCoreError::ObjectRecordMismatch { object_id });
    }

    // Objects never migrate chains: a mismatch here means a misbound
    // namespace, a cross-chain body transplant, or adapter corruption, never
    // a legitimate object. This runs before the inline/blob branch below so
    // a cross-chain blob record cannot slip past unchecked just because its
    // body is never fetched. No equivalent check exists for the recorded
    // protocol version.
    if record.provenance().chain_id() != chain_id {
        return Err(NodeCoreError::ObjectProvenanceMismatch { object_id });
    }

    match record.payload() {
        DurableObjectPayload::BlobReference(blob_digest) => {
            Ok(ObjectQueryResult::CurrentBlobReference {
                object_id,
                head_revision,
                object_version,
                digest,
                blob_digest: *blob_digest,
            })
        }
        DurableObjectPayload::Inline(inline) => {
            let object: &Object = inline.object();
            if object.id != object_id
                || object.version != object_version.get()
                || record.schema_version() != object.schema_version
            {
                return Err(NodeCoreError::ObjectRecordMismatch { object_id });
            }

            let body_length: usize = inline.canonical_bytes().len();
            if body_length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
                return Err(NodeCoreError::ObjectBodyTooLarge {
                    object_id,
                    actual: body_length,
                    maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
                });
            }

            let verified: bool = hashing::verify_digest(
                &record.digest(),
                HashPurpose::Object,
                record.provenance().protocol_version(),
                record.provenance().chain_id(),
                inline.canonical_bytes(),
            )
            .map_err(|error| match error {
                HashingError::UnsupportedAlgorithm(algorithm) => {
                    NodeCoreError::ObjectDigestUnverifiable {
                        object_id,
                        algorithm,
                    }
                }
                other => NodeCoreError::Hashing(other),
            })?;
            if !verified {
                return Err(NodeCoreError::ObjectBodyDigestMismatch { object_id });
            }

            // Corruption guard, not authorization: a public query never
            // authorizes a caller against the owner, but the head's owner
            // projection and the inline body's own typed owner must still
            // agree, exactly as `load_and_authorize_objects` requires.
            if head
                .owner_projection()
                .and_then(DurableObjectOwnerProjection::owner)
                != Some(&object.owner)
            {
                return Err(NodeCoreError::ObjectRecordMismatch { object_id });
            }

            Ok(ObjectQueryResult::CurrentInline {
                object_id,
                head_revision,
                object_version,
                digest,
                canonical_object_bytes: inline.canonical_bytes().to_vec(),
            })
        }
    }
}

/// Independently verified result of querying one durable receipt by request
/// id. Both statuses carry the exact `request_id` this result answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptQueryResult {
    /// No durable receipt exists for this request identifier.
    Absent {
        /// The exact request identifier this result answers.
        request_id: RequestId,
    },
    /// A durable receipt exists and was independently re-verified.
    Present {
        /// The exact request identifier this result answers.
        request_id: RequestId,
        /// Digest of the complete canonical input event that produced this receipt.
        event_digest: Digest32,
        /// The exact canonical [`NodeDedupRecord`], already re-encoding-checked.
        record: NodeDedupRecord,
    },
}

impl ReceiptQueryResult {
    /// Returns the exact request identifier this result answers, regardless
    /// of status.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        match self {
            Self::Absent { request_id } | Self::Present { request_id, .. } => *request_id,
        }
    }
}

/// Loads one durable receipt by request identifier and strictly validates it.
///
/// This decodes the persisted [`NodeDedupRecord`], checks it against the
/// outer durable receipt's own request identity and event digest, and then
/// requires the record to re-encode to exactly the persisted bytes — a
/// stricter check than the replay path applies, appropriate for a value
/// returned directly to an untrusted public caller.
pub fn query_request_receipt<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_id: RequestId,
) -> Result<ReceiptQueryResult, NodeCoreError>
where
    S: StructuredDurableDomainStateStore,
{
    let durable_request_id = DurableRequestId::new(*request_id.as_bytes()).map_err(|_| {
        NodeCoreError::PersistenceInvariant("validated request id failed durable projection")
    })?;
    let receipt = match store.get_request_receipt(context, domain, durable_request_id)? {
        Some(receipt) => receipt,
        None => return Ok(ReceiptQueryResult::Absent { request_id }),
    };
    if receipt.request_id() != durable_request_id {
        return Err(NodeCoreError::PersistenceInvariant(
            "durable receipt lookup returned another request",
        ));
    }
    let record = NodeDedupRecord::decode(receipt.canonical_bytes())
        .map_err(|_| NodeCoreError::PersistenceInvariant("invalid durable receipt"))?;
    if record.request_id() != request_id || record.event_digest() != receipt.event_digest() {
        return Err(NodeCoreError::PersistenceInvariant(
            "durable receipt projection and canonical record differ",
        ));
    }
    let re_encoded = record.encode()?;
    if re_encoded != receipt.canonical_bytes() {
        return Err(NodeCoreError::PersistenceInvariant(
            "durable receipt does not re-encode canonically",
        ));
    }
    Ok(ReceiptQueryResult::Present {
        request_id,
        event_digest: receipt.event_digest(),
        record,
    })
}
