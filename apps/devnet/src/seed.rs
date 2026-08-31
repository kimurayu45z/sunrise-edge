//! Idempotent, fail-closed asset-account seeding for the local devnet.

use crate::{
    asset_account::{
        AssetAccount, AssetAccountCodecError, DEVNET_ASSET_ID, asset_account_type_hash,
        decode_asset_account, encode_asset_account,
    },
    config::DevOwner,
    genesis::DEVNET_DOMAIN_BYTES,
};
use hashing::{HashSuiteResolver, HashingError, verify_digest};
use objects::{
    Address, Object, ObjectError, ObjectId, ObjectRef, Owner, encode_object, encode_object_ref,
};
use protocol_types::{AtomicityDomainId, Digest32, Epoch, HashPurpose};
use runtime::{
    DurableCommitOutcome, DurableCommitRejection, DurableInvocationError,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectOwnerProjection,
    DurableObjectPayload, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext, DurableReadError,
    DurableRequestId, DurableRequestReceipt, IndeterminateCommitReason, IndexedOutboxContractError,
    StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use std::{error::Error, fmt};

const SOURCE_SLOT: u64 = 1;
const DESTINATION_SLOT: u64 = 2;
const ASSET_ACCOUNT_SCHEMA_VERSION: u32 = 1;
const INITIAL_SOURCE_BALANCE: u64 = 1_000_000;
const INITIAL_DESTINATION_BALANCE: u64 = 0;
const INITIAL_SEQUENCE: u64 = 0;

/// The two deterministic asset-account references owned by one development address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeededAssetAccounts {
    owner: DevOwner,
    source: ObjectRef,
    destination: ObjectRef,
}

impl SeededAssetAccounts {
    /// Returns the configured development owner.
    #[must_use]
    pub const fn owner(&self) -> DevOwner {
        self.owner
    }

    /// Returns the currently authoritative funded/source account reference.
    #[must_use]
    pub const fn source(&self) -> &ObjectRef {
        &self.source
    }

    /// Returns the currently authoritative empty/destination account reference.
    #[must_use]
    pub const fn destination(&self) -> &ObjectRef {
        &self.destination
    }
}

/// Whether this boot created or verified an owner's seeded account pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedAssetAccountsOutcome {
    /// Both accounts and the seed receipt were committed atomically by this call.
    Created(SeededAssetAccounts),
    /// Both accounts and their immutable seed history already existed and were verified.
    Existing(SeededAssetAccounts),
}

impl SeedAssetAccountsOutcome {
    /// Returns the verified account pair regardless of whether this call created it.
    #[must_use]
    pub const fn accounts(&self) -> &SeededAssetAccounts {
        match self {
            Self::Created(accounts) | Self::Existing(accounts) => accounts,
        }
    }
}

#[derive(Clone, Debug)]
struct ExpectedSeedAccount {
    initial_object: Object,
    initial_digest: Digest32,
}

impl ExpectedSeedAccount {
    fn object_ref(&self) -> ObjectRef {
        ObjectRef {
            id: self.initial_object.id,
            version: self.initial_object.version,
            digest: self.initial_digest,
        }
    }
}

#[derive(Clone, Debug)]
struct ExpectedSeed {
    domain: AtomicityDomainId,
    source: ExpectedSeedAccount,
    destination: ExpectedSeedAccount,
    receipt: DurableRequestReceipt,
}

/// Seeds exactly two ordinary asset accounts for one development owner.
///
/// The account identifiers and receipt identity are deterministic for the
/// resolver, epoch, owner, and fixed source/destination slots. Creation is one
/// all-or-none structured durable transaction. A restart never overwrites
/// existing balances: it verifies both current immutable versions, their
/// version-one seed history, and the original receipt before returning.
pub fn seed_asset_accounts<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
) -> Result<SeedAssetAccountsOutcome, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    if context.writer_fence() != boot_generation {
        return Err(DevnetSeedError::ContextFenceMismatch {
            context: context.writer_fence(),
            boot: boot_generation,
        });
    }

    let expected: ExpectedSeed = build_expected_seed(resolver, epoch, owner)?;
    let source_head: DurableObjectHead = store
        .get_object_head(context, expected.domain, expected.source.initial_object.id)
        .map_err(DevnetSeedError::Read)?;
    let destination_head: DurableObjectHead = store
        .get_object_head(
            context,
            expected.domain,
            expected.destination.initial_object.id,
        )
        .map_err(DevnetSeedError::Read)?;

    match (&source_head, &destination_head) {
        (DurableObjectHead::Absent, DurableObjectHead::Absent) => {
            create_seed_accounts(store, resolver, owner, boot_generation, context, expected)
        }
        (DurableObjectHead::Current { .. }, DurableObjectHead::Current { .. }) => {
            let accounts: SeededAssetAccounts = verify_existing_seed(
                store,
                resolver,
                owner,
                boot_generation,
                context,
                &expected,
                &source_head,
                &destination_head,
            )?;
            Ok(SeedAssetAccountsOutcome::Existing(accounts))
        }
        _ => Err(DevnetSeedError::UnexpectedHeadPair {
            source: head_kind(&source_head),
            destination: head_kind(&destination_head),
        }),
    }
}

fn build_expected_seed(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    owner: DevOwner,
) -> Result<ExpectedSeed, DevnetSeedError> {
    let domain: AtomicityDomainId = AtomicityDomainId::new(DEVNET_DOMAIN_BYTES)
        .map_err(|_| DevnetSeedError::InvalidStaticDomain)?;
    let source_account: AssetAccount = AssetAccount {
        asset_id: DEVNET_ASSET_ID,
        balance: INITIAL_SOURCE_BALANCE,
        sequence: INITIAL_SEQUENCE,
    };
    let destination_account: AssetAccount = AssetAccount {
        asset_id: DEVNET_ASSET_ID,
        balance: INITIAL_DESTINATION_BALANCE,
        sequence: INITIAL_SEQUENCE,
    };
    let source: ExpectedSeedAccount =
        build_expected_account(resolver, epoch, owner, SOURCE_SLOT, source_account)?;
    let destination: ExpectedSeedAccount = build_expected_account(
        resolver,
        epoch,
        owner,
        DESTINATION_SLOT,
        destination_account,
    )?;
    if source.initial_object.id == destination.initial_object.id {
        return Err(DevnetSeedError::ObjectIdCollision);
    }

    // An ObjectRef is already a stable canonical record. Using the source's
    // immutable version-one reference as the seed receipt avoids inventing a
    // fourth devnet-local wire type beyond DR-0081's reserved 0xF001-0xF003.
    let receipt_bytes: Vec<u8> = encode_object_ref(&source.object_ref())?;
    let request_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Transaction, &receipt_bytes)?;
    let event_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::NodeEvent, &receipt_bytes)?;
    let request_id: DurableRequestId = DurableRequestId::new(request_digest.bytes())?;
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(request_id, event_digest, receipt_bytes)?;

    Ok(ExpectedSeed {
        domain,
        source,
        destination,
        receipt,
    })
}

fn build_expected_account(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    owner: DevOwner,
    slot: u64,
    account: AssetAccount,
) -> Result<ExpectedSeedAccount, DevnetSeedError> {
    let address_owner: Owner = Owner::Address(Address::new(*owner.as_bytes()));
    let body: Vec<u8> = encode_asset_account(&account)?;

    // The identifier descriptor reuses the existing canonical Object frame:
    // zero ObjectId is a descriptor namespace marker and `version` is the
    // explicit source/destination slot. The actual stored object never uses
    // either descriptor value. This avoids ad-hoc byte concatenation and a new
    // unratified canonical type identifier.
    let descriptor: Object = Object {
        id: ObjectId::new([0; 32]),
        version: slot,
        owner: address_owner.clone(),
        type_hash: asset_account_type_hash(),
        schema_version: ASSET_ACCOUNT_SCHEMA_VERSION,
        data: body.clone(),
    };
    let descriptor_bytes: Vec<u8> = encode_object(&descriptor)?;
    let object_id_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Object, &descriptor_bytes)?;
    let object: Object = Object {
        id: ObjectId::new(object_id_digest.bytes()),
        version: DurableObjectVersion::FIRST.get(),
        owner: address_owner,
        type_hash: asset_account_type_hash(),
        schema_version: ASSET_ACCOUNT_SCHEMA_VERSION,
        data: body,
    };
    let canonical_object: Vec<u8> = encode_object(&object)?;
    let initial_digest: Digest32 =
        resolver.hash_for_purpose(epoch, HashPurpose::Object, &canonical_object)?;
    Ok(ExpectedSeedAccount {
        initial_object: object,
        initial_digest,
    })
}

fn create_seed_accounts<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    expected: ExpectedSeed,
) -> Result<SeedAssetAccountsOutcome, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let provenance: DurableObjectProvenance =
        DurableObjectProvenance::new(resolver.chain_id().clone(), resolver.protocol_version());
    let source_record: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        expected.source.initial_object.clone(),
        expected.source.initial_digest,
        provenance.clone(),
        boot_generation.get(),
    )?;
    let destination_record: DurableObjectVersionRecord =
        DurableObjectVersionRecord::from_inline_object(
            expected.destination.initial_object.clone(),
            expected.destination.initial_digest,
            provenance,
            boot_generation.get(),
        )?;
    let owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(Address::new(*owner.as_bytes())))?;
    let routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    let reads: Vec<DurableObjectHeadRead> = vec![
        DurableObjectHeadRead::new(expected.source.initial_object.id, DurableObjectHead::Absent),
        DurableObjectHeadRead::new(
            expected.destination.initial_object.id,
            DurableObjectHead::Absent,
        ),
    ];
    let mutations: Vec<DurableObjectMutationEntry> = vec![
        DurableObjectMutationEntry::new(
            expected.source.initial_object.id,
            DurableObjectMutation::Create {
                version: source_record,
                owner_projection: owner_projection.clone(),
                routing_projection: routing_projection.clone(),
            },
        ),
        DurableObjectMutationEntry::new(
            expected.destination.initial_object.id,
            DurableObjectMutation::Create {
                version: destination_record,
                owner_projection,
                routing_projection,
            },
        ),
    ];
    let objects: DurableObjectChanges = DurableObjectChanges::new(reads, mutations)?;
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        expected.domain,
        None,
        objects,
        expected.receipt.clone(),
        None,
    )?;

    match store.commit_invocation(context, invocation) {
        DurableCommitOutcome::Committed => Ok(SeedAssetAccountsOutcome::Created(initial_accounts(
            owner, &expected,
        ))),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::ObjectConflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => reconcile_existing_seed(store, resolver, owner, boot_generation, context, &expected),
        DurableCommitOutcome::Rejected(rejection) => {
            Err(DevnetSeedError::CommitRejected(rejection))
        }
        DurableCommitOutcome::Indeterminate(reason) => {
            let receipt: Option<DurableRequestReceipt> = store
                .get_request_receipt(context, expected.domain, expected.receipt.request_id())
                .map_err(DevnetSeedError::Read)?;
            match receipt {
                Some(receipt) if receipt == expected.receipt => reconcile_existing_seed(
                    store,
                    resolver,
                    owner,
                    boot_generation,
                    context,
                    &expected,
                ),
                Some(_) => Err(DevnetSeedError::ReceiptMismatch),
                None => Err(DevnetSeedError::CommitIndeterminate(reason)),
            }
        }
    }
}

fn reconcile_existing_seed<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    expected: &ExpectedSeed,
) -> Result<SeedAssetAccountsOutcome, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let source_head: DurableObjectHead = store
        .get_object_head(context, expected.domain, expected.source.initial_object.id)
        .map_err(DevnetSeedError::Read)?;
    let destination_head: DurableObjectHead = store
        .get_object_head(
            context,
            expected.domain,
            expected.destination.initial_object.id,
        )
        .map_err(DevnetSeedError::Read)?;
    let accounts: SeededAssetAccounts = verify_existing_seed(
        store,
        resolver,
        owner,
        boot_generation,
        context,
        expected,
        &source_head,
        &destination_head,
    )?;
    Ok(SeedAssetAccountsOutcome::Existing(accounts))
}

#[allow(clippy::too_many_arguments)]
fn verify_existing_seed<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    owner: DevOwner,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    expected: &ExpectedSeed,
    source_head: &DurableObjectHead,
    destination_head: &DurableObjectHead,
) -> Result<SeededAssetAccounts, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    if !matches!(source_head, DurableObjectHead::Current { .. })
        || !matches!(destination_head, DurableObjectHead::Current { .. })
    {
        return Err(DevnetSeedError::UnexpectedHeadPair {
            source: head_kind(source_head),
            destination: head_kind(destination_head),
        });
    }

    let source: VerifiedCurrentAccount = verify_current_account(
        store,
        resolver,
        boot_generation,
        context,
        expected.domain,
        source_head,
        &expected.source,
        owner,
    )?;
    let destination: VerifiedCurrentAccount = verify_current_account(
        store,
        resolver,
        boot_generation,
        context,
        expected.domain,
        destination_head,
        &expected.destination,
        owner,
    )?;

    let combined_balance: u64 = source
        .account
        .balance
        .checked_add(destination.account.balance)
        .ok_or(DevnetSeedError::AssetInvariantViolation)?;
    if combined_balance != INITIAL_SOURCE_BALANCE
        || source.account.sequence != destination.account.sequence
    {
        return Err(DevnetSeedError::AssetInvariantViolation);
    }

    verify_initial_record(
        store,
        resolver,
        boot_generation,
        context,
        expected.domain,
        &expected.source,
        owner,
    )?;
    verify_initial_record(
        store,
        resolver,
        boot_generation,
        context,
        expected.domain,
        &expected.destination,
        owner,
    )?;
    verify_seed_receipt(store, context, expected)?;

    Ok(SeededAssetAccounts {
        owner,
        source: source.object_ref,
        destination: destination.object_ref,
    })
}

#[derive(Debug)]
struct VerifiedCurrentAccount {
    object_ref: ObjectRef,
    account: AssetAccount,
}

#[allow(clippy::too_many_arguments)]
fn verify_current_account<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    head: &DurableObjectHead,
    expected: &ExpectedSeedAccount,
    owner: DevOwner,
) -> Result<VerifiedCurrentAccount, DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let (object_version, head_digest, owner_projection, routing_projection): (
        DurableObjectVersion,
        Digest32,
        &DurableObjectOwnerProjection,
        &DurableObjectRoutingProjection,
    ) = match head {
        DurableObjectHead::Current {
            object_version,
            digest,
            owner_projection,
            routing_projection,
            ..
        } => (
            *object_version,
            *digest,
            owner_projection,
            routing_projection,
        ),
        DurableObjectHead::Absent | DurableObjectHead::Tombstoned { .. } => {
            return Err(DevnetSeedError::StoredObjectMismatch {
                object_id: expected.initial_object.id,
                detail: "object head is not current",
            });
        }
    };
    let expected_owner: Owner = Owner::Address(Address::new(*owner.as_bytes()));
    let expected_owner_projection: DurableObjectOwnerProjection =
        DurableObjectOwnerProjection::from_owner(expected_owner.clone())?;
    let expected_routing_projection: DurableObjectRoutingProjection =
        DurableObjectRoutingProjection::new(None)?;
    if owner_projection != &expected_owner_projection
        || routing_projection != &expected_routing_projection
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "head owner or routing projection differs",
        });
    }

    let record: DurableObjectVersionRecord = store
        .get_object_version(context, domain, expected.initial_object.id, object_version)
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingObjectVersion {
            object_id: expected.initial_object.id,
            version: object_version,
        })?;
    if record.object_id() != expected.initial_object.id
        || record.object_version() != object_version
        || record.digest() != head_digest
        || record.schema_version() != ASSET_ACCOUNT_SCHEMA_VERSION
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "head and immutable metadata differ",
        });
    }
    verify_record_context(&record, resolver, boot_generation)?;
    let inline = match record.payload() {
        DurableObjectPayload::Inline(inline) => inline,
        DurableObjectPayload::BlobReference(_) => {
            return Err(DevnetSeedError::BlobBackedSeedObject(
                expected.initial_object.id,
            ));
        }
    };
    let object: &Object = inline.object();
    if object.id != expected.initial_object.id
        || object.version != object_version.get()
        || object.owner != expected_owner
        || object.type_hash != asset_account_type_hash()
        || object.schema_version != ASSET_ACCOUNT_SCHEMA_VERSION
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "typed object identity, owner, type, or schema differs",
        });
    }
    let canonical_object: Vec<u8> = encode_object(object)?;
    if inline.canonical_bytes() != canonical_object {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "stored object bytes are not the exact canonical encoding",
        });
    }
    let digest_valid: bool = verify_digest(
        &record.digest(),
        HashPurpose::Object,
        record.provenance().protocol_version(),
        record.provenance().chain_id(),
        inline.canonical_bytes(),
    )?;
    if !digest_valid {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "stored object digest does not verify",
        });
    }
    let account: AssetAccount = decode_asset_account(&object.data)?;
    if account.asset_id != DEVNET_ASSET_ID || encode_asset_account(&account)? != object.data {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "asset-account body or asset identifier differs",
        });
    }
    Ok(VerifiedCurrentAccount {
        object_ref: ObjectRef {
            id: object.id,
            version: object.version,
            digest: record.digest(),
        },
        account,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_initial_record<S>(
    store: &S,
    resolver: &HashSuiteResolver,
    boot_generation: WriterFenceGeneration,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected: &ExpectedSeedAccount,
    owner: DevOwner,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let record: DurableObjectVersionRecord = store
        .get_object_version(
            context,
            domain,
            expected.initial_object.id,
            DurableObjectVersion::FIRST,
        )
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingObjectVersion {
            object_id: expected.initial_object.id,
            version: DurableObjectVersion::FIRST,
        })?;
    verify_record_context(&record, resolver, boot_generation)?;
    let inline = match record.payload() {
        DurableObjectPayload::Inline(inline) => inline,
        DurableObjectPayload::BlobReference(_) => {
            return Err(DevnetSeedError::BlobBackedSeedObject(
                expected.initial_object.id,
            ));
        }
    };
    let expected_owner: Owner = Owner::Address(Address::new(*owner.as_bytes()));
    let canonical_expected: Vec<u8> = encode_object(&expected.initial_object)?;
    if record.object_id() != expected.initial_object.id
        || record.object_version() != DurableObjectVersion::FIRST
        || record.digest() != expected.initial_digest
        || record.schema_version() != ASSET_ACCOUNT_SCHEMA_VERSION
        || inline.object() != &expected.initial_object
        || inline.object().owner != expected_owner
        || inline.canonical_bytes() != canonical_expected
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "immutable version-one seed record differs",
        });
    }
    let digest_valid: bool = verify_digest(
        &record.digest(),
        HashPurpose::Object,
        record.provenance().protocol_version(),
        record.provenance().chain_id(),
        inline.canonical_bytes(),
    )?;
    if !digest_valid {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: expected.initial_object.id,
            detail: "immutable version-one seed digest does not verify",
        });
    }
    Ok(())
}

fn verify_record_context(
    record: &DurableObjectVersionRecord,
    resolver: &HashSuiteResolver,
    boot_generation: WriterFenceGeneration,
) -> Result<(), DevnetSeedError> {
    if record.provenance().chain_id() != resolver.chain_id()
        || record.provenance().protocol_version() != resolver.protocol_version()
    {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: record.object_id(),
            detail: "creating chain or protocol-version provenance differs",
        });
    }
    let checkpoint: u64 = record.created_checkpoint();
    if checkpoint == 0 || checkpoint > boot_generation.get() {
        return Err(DevnetSeedError::StoredObjectMismatch {
            object_id: record.object_id(),
            detail: "created checkpoint is zero or from a future boot generation",
        });
    }
    Ok(())
}

fn verify_seed_receipt<S>(
    store: &S,
    context: &DurableOperationContext,
    expected: &ExpectedSeed,
) -> Result<(), DevnetSeedError>
where
    S: StructuredDurableDomainStateStore + ?Sized,
{
    let receipt: DurableRequestReceipt = store
        .get_request_receipt(context, expected.domain, expected.receipt.request_id())
        .map_err(DevnetSeedError::Read)?
        .ok_or(DevnetSeedError::MissingSeedReceipt)?;
    if receipt != expected.receipt {
        return Err(DevnetSeedError::ReceiptMismatch);
    }
    Ok(())
}

fn initial_accounts(owner: DevOwner, expected: &ExpectedSeed) -> SeededAssetAccounts {
    SeededAssetAccounts {
        owner,
        source: expected.source.object_ref(),
        destination: expected.destination.object_ref(),
    }
}

fn head_kind(head: &DurableObjectHead) -> &'static str {
    match head {
        DurableObjectHead::Absent => "absent",
        DurableObjectHead::Tombstoned { .. } => "tombstoned",
        DurableObjectHead::Current { .. } => "current",
    }
}

/// Fail-closed errors while deriving, creating, or verifying devnet seed objects.
#[derive(Debug)]
pub enum DevnetSeedError {
    /// The hard-coded devnet atomicity domain unexpectedly violated its invariant.
    InvalidStaticDomain,
    /// The supplied operation context does not carry this boot's writer fence.
    ContextFenceMismatch {
        /// Fence carried by the operation context.
        context: WriterFenceGeneration,
        /// Fence exclusively claimed by this boot.
        boot: WriterFenceGeneration,
    },
    /// Hash derivation produced the same identifier for both explicit slots.
    ObjectIdCollision,
    /// The strict asset-account body codec rejected a value.
    AssetCodec(AssetAccountCodecError),
    /// Existing object framing failed.
    Object(ObjectError),
    /// Domain-separated hash derivation or verification failed.
    Hashing(HashingError),
    /// The bounded durable envelope was invalid.
    Invocation(DurableInvocationError),
    /// A deterministic non-zero durable request identity could not be built.
    RequestIdentity(IndexedOutboxContractError),
    /// A structured read failed.
    Read(DurableReadError),
    /// The pair was not exactly both absent or both current.
    UnexpectedHeadPair {
        /// Source head kind.
        source: &'static str,
        /// Destination head kind.
        destination: &'static str,
    },
    /// An exact immutable version referenced by a current or seed head was missing.
    MissingObjectVersion {
        /// Missing object's identity.
        object_id: ObjectId,
        /// Missing immutable version.
        version: DurableObjectVersion,
    },
    /// A seed object was blob-backed, which this local profile does not support.
    BlobBackedSeedObject(ObjectId),
    /// Stored object metadata, bytes, digest, or provenance did not match.
    StoredObjectMismatch {
        /// Mismatched object's identity.
        object_id: ObjectId,
        /// Stable operator-facing mismatch category.
        detail: &'static str,
    },
    /// Current balances or sequences violated the bundled transfer invariant.
    AssetInvariantViolation,
    /// The deterministic original seed receipt was absent.
    MissingSeedReceipt,
    /// The deterministic seed request identity resolved to different receipt bytes.
    ReceiptMismatch,
    /// The store proved that seed creation did not commit.
    CommitRejected(DurableCommitRejection),
    /// The store could not determine whether seed creation committed.
    CommitIndeterminate(IndeterminateCommitReason),
}

impl fmt::Display for DevnetSeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStaticDomain => f.write_str("devnet's fixed atomicity domain is invalid"),
            Self::ContextFenceMismatch { context, boot } => write!(
                f,
                "seed context fence {} differs from boot generation {}",
                context.get(),
                boot.get()
            ),
            Self::ObjectIdCollision => {
                f.write_str("devnet source and destination object identifiers collided")
            }
            Self::AssetCodec(error) => write!(f, "seed asset-account codec failed: {error}"),
            Self::Object(error) => write!(f, "seed object framing failed: {error}"),
            Self::Hashing(error) => write!(f, "seed hash derivation failed: {error}"),
            Self::Invocation(error) => write!(f, "seed durable envelope is invalid: {error}"),
            Self::RequestIdentity(error) => {
                write!(f, "seed request identity is invalid: {error}")
            }
            Self::Read(error) => write!(f, "seed structured read failed: {error:?}"),
            Self::UnexpectedHeadPair {
                source,
                destination,
            } => write!(
                f,
                "seed account heads must be both absent or both current, got source={source}, destination={destination}"
            ),
            Self::MissingObjectVersion { object_id, version } => write!(
                f,
                "seed object {object_id} immutable version {} is missing",
                version.get()
            ),
            Self::BlobBackedSeedObject(object_id) => write!(
                f,
                "seed object {object_id} is blob-backed, unsupported by the local profile"
            ),
            Self::StoredObjectMismatch { object_id, detail } => {
                write!(f, "seed object {object_id} failed verification: {detail}")
            }
            Self::AssetInvariantViolation => f.write_str(
                "seed asset accounts violate conserved balance or paired-sequence invariants",
            ),
            Self::MissingSeedReceipt => f.write_str("deterministic seed receipt is missing"),
            Self::ReceiptMismatch => f.write_str("deterministic seed receipt differs"),
            Self::CommitRejected(rejection) => {
                write!(f, "seed commit was rejected: {rejection:?}")
            }
            Self::CommitIndeterminate(reason) => {
                write!(f, "seed commit is indeterminate: {reason:?}")
            }
        }
    }
}

impl Error for DevnetSeedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AssetCodec(error) => Some(error),
            Self::Object(error) => Some(error),
            Self::Hashing(error) => Some(error),
            Self::Invocation(error) => Some(error),
            Self::RequestIdentity(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AssetAccountCodecError> for DevnetSeedError {
    fn from(value: AssetAccountCodecError) -> Self {
        Self::AssetCodec(value)
    }
}

impl From<ObjectError> for DevnetSeedError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

impl From<HashingError> for DevnetSeedError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

impl From<DurableInvocationError> for DevnetSeedError {
    fn from(value: DurableInvocationError) -> Self {
        Self::Invocation(value)
    }
}

impl From<IndexedOutboxContractError> for DevnetSeedError {
    fn from(value: IndexedOutboxContractError) -> Self {
        Self::RequestIdentity(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashSuite, HashSuiteSchedule, ProtocolVersion};
    use runtime::{MemoryDurableStateStore, StorageCorrelationId, StorageDeadline};

    fn resolver() -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("seed-test-chain").unwrap(),
            ProtocolVersion::new(3),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    fn generation() -> WriterFenceGeneration {
        WriterFenceGeneration::new(2).unwrap()
    }

    fn context() -> DurableOperationContext {
        DurableOperationContext::new(
            generation(),
            StorageDeadline::new(1_000).unwrap(),
            StorageCorrelationId::new([0x51; 16]).unwrap(),
        )
    }

    fn domain() -> AtomicityDomainId {
        AtomicityDomainId::new(DEVNET_DOMAIN_BYTES).unwrap()
    }

    #[test]
    fn seed_is_atomic_distinct_and_idempotent() {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new_bound(domain(), generation());
        store.set_time(0);
        let owner: DevOwner = DevOwner::new([0x61; 32]);
        let resolver: HashSuiteResolver = resolver();

        let created: SeedAssetAccountsOutcome = seed_asset_accounts(
            &store,
            &resolver,
            Epoch::new(0),
            owner,
            generation(),
            &context(),
        )
        .unwrap();
        assert!(matches!(created, SeedAssetAccountsOutcome::Created(_)));
        assert_ne!(
            created.accounts().source().id,
            created.accounts().destination().id
        );

        let existing: SeedAssetAccountsOutcome = seed_asset_accounts(
            &store,
            &resolver,
            Epoch::new(0),
            owner,
            generation(),
            &context(),
        )
        .unwrap();
        assert!(matches!(existing, SeedAssetAccountsOutcome::Existing(_)));
        assert_eq!(created.accounts(), existing.accounts());
    }

    #[test]
    fn deterministic_ids_are_owner_scoped() {
        let resolver: HashSuiteResolver = resolver();
        let first: ExpectedSeed =
            build_expected_seed(&resolver, Epoch::new(0), DevOwner::new([0x71; 32])).unwrap();
        let second: ExpectedSeed =
            build_expected_seed(&resolver, Epoch::new(0), DevOwner::new([0x72; 32])).unwrap();

        assert_ne!(
            first.source.initial_object.id,
            first.destination.initial_object.id
        );
        assert_ne!(
            first.source.initial_object.id,
            second.source.initial_object.id
        );
    }
}
