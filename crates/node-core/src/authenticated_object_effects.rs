//! Fail-closed translation from verified owned-object inputs to durable mutations.
//!
//! This module is intentionally private to `node-core`. Callers cannot construct
//! [`VerifiedAuthenticatedObject`] values from request bytes: the only production
//! constructor is the storage-loading path that has already checked the signed
//! reference, immutable version record, provenance, digest, owner, and body bounds.

use super::{
    MAX_AUTHENTICATED_OBJECT_BODY_BYTES, MAX_AUTHENTICATED_OBJECT_READS,
    MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES, NodeCoreError,
};
use execution::ObjectEffect;
use hashing::HashSuiteResolver;
use objects::{AccessMode, Object, ObjectId, Owner, encode_object};
use protocol_types::{ChainId, Epoch, HashPurpose, ProtocolVersion};
use runtime::{
    DurableInvocationError, DurableObjectHead, DurableObjectHeadRead, DurableObjectMutation,
    DurableObjectMutationEntry, DurableObjectOwnerProjection, DurableObjectProvenance,
    DurableObjectVersionRecord,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifiedAuthenticatedObject {
    mode: AccessMode,
    head: DurableObjectHead,
    object: Object,
}

impl VerifiedAuthenticatedObject {
    const fn new(mode: AccessMode, head: DurableObjectHead, object: Object) -> Self {
        Self { mode, head, object }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct LoadedAuthenticatedObjects {
    reads: Vec<DurableObjectHeadRead>,
    verified: Vec<VerifiedAuthenticatedObject>,
    total_body_bytes: usize,
}

impl LoadedAuthenticatedObjects {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            reads: Vec::with_capacity(capacity),
            verified: Vec::with_capacity(capacity),
            total_body_bytes: 0,
        }
    }

    pub(super) fn push(
        &mut self,
        object_id: ObjectId,
        mode: AccessMode,
        head: DurableObjectHead,
        object: Object,
    ) {
        self.reads
            .push(DurableObjectHeadRead::new(object_id, head.clone()));
        self.verified
            .push(VerifiedAuthenticatedObject::new(mode, head, object));
    }

    pub(super) fn verified(&self) -> &[VerifiedAuthenticatedObject] {
        &self.verified
    }

    /// Records the already bounds-checked total inline body bytes loaded for
    /// this invocation's verified objects, so the effect translator can share
    /// one aggregate budget with the loader instead of starting a second one.
    pub(super) fn set_total_body_bytes(&mut self, total_body_bytes: usize) {
        self.total_body_bytes = total_body_bytes;
    }

    pub(super) fn total_body_bytes(&self) -> usize {
        self.total_body_bytes
    }

    pub(super) fn into_reads(self) -> Vec<DurableObjectHeadRead> {
        self.reads
    }
}

/// Trusted context required only when execution creates a new immutable version.
///
/// The caller must construct this only from the already-validated event
/// context (the same `chain_id`, `protocol_version`, and `epoch` the ingress
/// path verified before dispatch), never from unauthenticated request input.
/// `created_checkpoint` is trusted verbatim by this module: it is not
/// re-derived or bounded here, so the future call site that supplies it is
/// responsible for enforcing that checkpoints are monotonically
/// non-decreasing across an object's version history before constructing
/// this context.
pub(super) struct TrustedObjectMutationContext<'a> {
    pub(super) resolver: &'a HashSuiteResolver,
    pub(super) chain_id: &'a ChainId,
    pub(super) protocol_version: ProtocolVersion,
    pub(super) epoch: Epoch,
    pub(super) created_checkpoint: u64,
}

/// Validates exact signed-access/effect correspondence and builds durable mutations.
///
/// The current live handler calls this with an empty effect list after loading
/// read-only inputs. The Write/Consume execution integration will supply a trusted
/// mutation context in the next Developer MVP slice; until then the ingress path
/// continues to reject those access modes before storage I/O.
///
/// `loaded_body_bytes` is the already bounds-checked total inline body bytes
/// the loader read for `verified` (see
/// [`LoadedAuthenticatedObjects::total_body_bytes`]). New update bodies are
/// added on top of it so old verified bodies and new update bodies share one
/// `MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES` budget instead of two
/// independent budgets.
pub(super) fn translate_authenticated_object_effects(
    verified: &[VerifiedAuthenticatedObject],
    effects: &[ObjectEffect],
    context: Option<&TrustedObjectMutationContext<'_>>,
    loaded_body_bytes: usize,
) -> Result<Vec<DurableObjectMutationEntry>, NodeCoreError> {
    if effects.len() > MAX_AUTHENTICATED_OBJECT_READS {
        return Err(NodeCoreError::TooManyObjectEffects {
            actual: effects.len(),
            maximum: MAX_AUTHENTICATED_OBJECT_READS,
        });
    }
    let mut effects_by_id: BTreeMap<ObjectId, &ObjectEffect> = BTreeMap::new();
    for effect in effects {
        let object_id: ObjectId = match effect {
            ObjectEffect::Created(object) => {
                return Err(NodeCoreError::ObjectCreationUnsupported {
                    object_id: object.id,
                });
            }
            ObjectEffect::Mutated { new_object, .. } => new_object.id,
            ObjectEffect::Deleted { id, .. } => *id,
        };
        if effects_by_id.insert(object_id, effect).is_some() {
            return Err(NodeCoreError::DuplicateObjectEffect { object_id });
        }
    }

    let mut mutations: Vec<DurableObjectMutationEntry> = Vec::new();
    let mut represented_body_bytes: usize = loaded_body_bytes;
    for input in verified {
        let object_id: ObjectId = input.object.id;
        let effect: Option<&ObjectEffect> = effects_by_id.remove(&object_id);
        match input.mode {
            AccessMode::Read => {
                if effect.is_some() {
                    return Err(NodeCoreError::ObjectEffectMismatch {
                        object_id,
                        reason: "read access produced a mutation effect",
                    });
                }
            }
            AccessMode::Write => {
                let Some(ObjectEffect::Mutated {
                    previous_version,
                    new_object,
                }) = effect
                else {
                    return Err(NodeCoreError::ObjectEffectMismatch {
                        object_id,
                        reason: "write access requires exactly one mutated effect",
                    });
                };
                let mutation: DurableObjectMutation = translate_update(
                    input,
                    *previous_version,
                    new_object,
                    context,
                    &mut represented_body_bytes,
                )?;
                mutations.push(DurableObjectMutationEntry::new(object_id, mutation));
            }
            AccessMode::Consume => {
                let Some(ObjectEffect::Deleted { id, version }) = effect else {
                    return Err(NodeCoreError::ObjectEffectMismatch {
                        object_id,
                        reason: "consume access requires exactly one deleted effect",
                    });
                };
                if *id != object_id || *version != input.object.version {
                    return Err(NodeCoreError::ObjectEffectMismatch {
                        object_id,
                        reason: "deleted effect identity or version disagrees with verified input",
                    });
                }
                require_mutable_address_owner(input)?;
                mutations.push(DurableObjectMutationEntry::new(
                    object_id,
                    DurableObjectMutation::Delete,
                ));
            }
        }
    }

    if let Some((&object_id, _)) = effects_by_id.first_key_value() {
        return Err(NodeCoreError::UndeclaredObjectEffect { object_id });
    }
    Ok(mutations)
}

fn translate_update(
    input: &VerifiedAuthenticatedObject,
    previous_version: u64,
    new_object: &Object,
    context: Option<&TrustedObjectMutationContext<'_>>,
    represented_body_bytes: &mut usize,
) -> Result<DurableObjectMutation, NodeCoreError> {
    let object_id: ObjectId = input.object.id;
    require_mutable_address_owner(input)?;
    if previous_version != input.object.version || new_object.id != object_id {
        return Err(NodeCoreError::ObjectEffectMismatch {
            object_id,
            reason: "mutated effect identity or previous version disagrees with verified input",
        });
    }
    let next_version: u64 = input
        .object
        .version
        .checked_add(1)
        .ok_or(NodeCoreError::ObjectVersionOverflow { object_id })?;
    if new_object.version != next_version {
        return Err(NodeCoreError::ObjectEffectMismatch {
            object_id,
            reason: "mutated effect did not advance by exactly one version",
        });
    }
    if new_object.owner != input.object.owner
        || new_object.type_hash != input.object.type_hash
        || new_object.schema_version != input.object.schema_version
    {
        return Err(NodeCoreError::ObjectEffectMismatch {
            object_id,
            reason: "mutated effect changed owner, type, or schema",
        });
    }

    let canonical_bytes: Vec<u8> = encode_object(new_object)
        .map_err(DurableInvocationError::from)
        .map_err(NodeCoreError::from)?;
    let body_length: usize = canonical_bytes.len();
    if body_length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(NodeCoreError::ObjectBodyTooLarge {
            object_id,
            actual: body_length,
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        });
    }
    *represented_body_bytes = represented_body_bytes.checked_add(body_length).ok_or(
        NodeCoreError::ObjectBodyTooLarge {
            object_id,
            actual: usize::MAX,
            maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
        },
    )?;
    if *represented_body_bytes > MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES {
        return Err(NodeCoreError::ObjectBodyTooLarge {
            object_id,
            actual: *represented_body_bytes,
            maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
        });
    }

    let context: &TrustedObjectMutationContext<'_> =
        context.ok_or(NodeCoreError::ObjectMutationContextMissing { object_id })?;
    if context.resolver.chain_id() != context.chain_id
        || context.resolver.protocol_version() != context.protocol_version
    {
        return Err(NodeCoreError::ObjectEffectMismatch {
            object_id,
            reason: "trusted object mutation and hash resolver contexts disagree",
        });
    }
    let digest =
        context
            .resolver
            .hash_for_purpose(context.epoch, HashPurpose::Object, &canonical_bytes)?;
    let provenance =
        DurableObjectProvenance::new(context.chain_id.clone(), context.protocol_version);
    let version = DurableObjectVersionRecord::from_inline_object(
        new_object.clone(),
        digest,
        provenance,
        context.created_checkpoint,
    )?;
    let owner_projection = DurableObjectOwnerProjection::from_owner(new_object.owner.clone())?;
    let routing_projection = match &input.head {
        DurableObjectHead::Current {
            routing_projection, ..
        } => routing_projection.clone(),
        DurableObjectHead::Absent | DurableObjectHead::Tombstoned { .. } => {
            return Err(NodeCoreError::ObjectEffectMismatch {
                object_id,
                reason: "verified mutation input did not have a current head",
            });
        }
    };
    Ok(DurableObjectMutation::Update {
        version,
        owner_projection,
        routing_projection,
    })
}

fn require_mutable_address_owner(input: &VerifiedAuthenticatedObject) -> Result<(), NodeCoreError> {
    match input.object.owner {
        Owner::Address(_) => Ok(()),
        Owner::Immutable | Owner::Shared | Owner::System => {
            Err(NodeCoreError::ObjectOwnerKindUnsupported {
                object_id: input.object.id,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashing::verify_digest;
    use objects::Address;
    use protocol_types::{Digest32, HashAlgorithmId, HashSuite, HashSuiteSchedule};
    use runtime::{DurableObjectRoutingProjection, DurableObjectVersion, ObjectHeadRevision};

    fn resolver() -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("sunrise-mvp").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    fn object(version: u64, owner: Owner, data: Vec<u8>) -> Object {
        Object {
            id: ObjectId::new([0x41; 32]),
            version,
            owner,
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x42; 32]),
            schema_version: 7,
            data,
        }
    }

    fn verified(mode: AccessMode, object: Object) -> VerifiedAuthenticatedObject {
        let owner_projection =
            DurableObjectOwnerProjection::from_owner(object.owner.clone()).unwrap();
        let head = DurableObjectHead::Current {
            head_revision: ObjectHeadRevision::FIRST,
            object_version: DurableObjectVersion::new(object.version).unwrap(),
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x43; 32]),
            owner_projection,
            routing_projection: DurableObjectRoutingProjection::new(Some(vec![0x44])).unwrap(),
        };
        VerifiedAuthenticatedObject::new(mode, head, object)
    }

    #[test]
    fn verified_write_translates_to_one_durable_update() {
        let owner = Owner::Address(Address::new([0x45; 32]));
        let current = object(9, owner, vec![0x01]);
        let mut next = current.clone();
        next.version = 10;
        next.data = vec![0x02, 0x03];
        let resolver = resolver();
        let chain_id = ChainId::new("sunrise-mvp").unwrap();
        let context = TrustedObjectMutationContext {
            resolver: &resolver,
            chain_id: &chain_id,
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(3),
            created_checkpoint: 17,
        };

        let mutations = translate_authenticated_object_effects(
            &[verified(AccessMode::Write, current)],
            &[ObjectEffect::Mutated {
                previous_version: 9,
                new_object: next.clone(),
            }],
            Some(&context),
            0,
        )
        .unwrap();

        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].object_id(), next.id);
        let DurableObjectMutation::Update {
            version,
            owner_projection,
            routing_projection,
        } = mutations[0].mutation()
        else {
            panic!("write effect did not translate to an update");
        };
        assert_eq!(version.object_version().get(), 10);
        assert_eq!(version.created_checkpoint(), 17);
        assert_eq!(version.payload().inline().unwrap().object(), &next);
        assert_eq!(
            version.provenance().chain_id(),
            &ChainId::new("sunrise-mvp").unwrap()
        );
        assert_eq!(
            version.provenance().protocol_version(),
            ProtocolVersion::new(1)
        );
        assert!(
            verify_digest(
                &version.digest(),
                HashPurpose::Object,
                version.provenance().protocol_version(),
                version.provenance().chain_id(),
                version.payload().inline().unwrap().canonical_bytes(),
            )
            .unwrap()
        );
        assert_eq!(
            owner_projection,
            &DurableObjectOwnerProjection::from_owner(next.owner.clone()).unwrap()
        );
        assert_eq!(routing_projection.bytes(), Some([0x44].as_slice()));
    }

    #[test]
    fn verified_consume_translates_to_one_durable_delete() {
        let current = object(4, Owner::Address(Address::new([0x46; 32])), vec![0x05]);
        let mutations = translate_authenticated_object_effects(
            &[verified(AccessMode::Consume, current.clone())],
            &[ObjectEffect::Deleted {
                id: current.id,
                version: current.version,
            }],
            None,
            0,
        )
        .unwrap();

        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].mutation(), &DurableObjectMutation::Delete);
    }

    #[test]
    fn read_only_inputs_accept_no_effects_and_reject_mutations() {
        let current = object(2, Owner::Address(Address::new([0x47; 32])), vec![0x06]);
        assert_eq!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Read, current.clone())],
                &[],
                None,
                0,
            ),
            Ok(Vec::new())
        );
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Read, current.clone())],
                &[ObjectEffect::Deleted {
                    id: current.id,
                    version: current.version,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn effect_translation_rejects_undeclared_duplicate_and_created_effects() {
        let first = object(1, Owner::Address(Address::new([0x48; 32])), vec![0x07]);
        let mut undeclared = first.clone();
        undeclared.id = ObjectId::new([0x49; 32]);
        let duplicate_effect = ObjectEffect::Deleted {
            id: first.id,
            version: first.version,
        };
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Read, first.clone())],
                &[ObjectEffect::Deleted {
                    id: undeclared.id,
                    version: undeclared.version,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::UndeclaredObjectEffect { .. })
        ));
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Consume, first.clone())],
                &[duplicate_effect.clone(), duplicate_effect],
                None,
                0,
            ),
            Err(NodeCoreError::DuplicateObjectEffect { .. })
        ));
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Read, first)],
                &[ObjectEffect::Created(undeclared)],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectCreationUnsupported { .. })
        ));

        let excessive_effects: Vec<ObjectEffect> = (0..=MAX_AUTHENTICATED_OBJECT_READS)
            .map(|index: usize| ObjectEffect::Deleted {
                id: ObjectId::new([u8::try_from(index).unwrap(); 32]),
                version: 1,
            })
            .collect();
        assert_eq!(
            translate_authenticated_object_effects(&[], &excessive_effects, None, 0),
            Err(NodeCoreError::TooManyObjectEffects {
                actual: MAX_AUTHENTICATED_OBJECT_READS + 1,
                maximum: MAX_AUTHENTICATED_OBJECT_READS,
            })
        );
    }

    #[test]
    fn effect_translation_rejects_version_owner_type_and_context_mismatches() {
        let current = object(
            u64::MAX,
            Owner::Address(Address::new([0x50; 32])),
            vec![0x08],
        );
        let mut next = current.clone();
        next.data = vec![0x09];
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectVersionOverflow { .. })
        ));

        let immutable = object(1, Owner::Immutable, vec![0x0a]);
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Consume, immutable.clone())],
                &[ObjectEffect::Deleted {
                    id: immutable.id,
                    version: immutable.version,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectOwnerKindUnsupported { .. })
        ));

        let current = object(8, Owner::Address(Address::new([0x51; 32])), vec![0x0b]);
        let mut next = current.clone();
        next.version = 9;
        next.data = vec![0x0c];
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next.clone(),
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectMutationContextMissing { .. })
        ));

        let resolver = resolver();
        let wrong_chain_id = ChainId::new("other-chain").unwrap();
        let mismatched_context = TrustedObjectMutationContext {
            resolver: &resolver,
            chain_id: &wrong_chain_id,
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(0),
            created_checkpoint: 1,
        };
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next.clone(),
                }],
                Some(&mismatched_context),
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));

        let chain_id = ChainId::new("sunrise-mvp").unwrap();
        let context = TrustedObjectMutationContext {
            resolver: &resolver,
            chain_id: &chain_id,
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(0),
            created_checkpoint: 1,
        };
        next.owner = Owner::Address(Address::new([0x52; 32]));
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next,
                }],
                Some(&context),
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));

        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current)],
                &[],
                Some(&context),
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn write_effect_must_advance_version_by_exactly_one() {
        let current = object(5, Owner::Address(Address::new([0x53; 32])), vec![0x0d]);
        let mut next = current.clone();
        next.version = 7;
        next.data = vec![0x0e];
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn write_effect_rejects_wrong_previous_version() {
        let current = object(5, Owner::Address(Address::new([0x54; 32])), vec![0x0f]);
        let mut next = current.clone();
        next.version = 6;
        next.data = vec![0x10];
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version.wrapping_sub(1),
                    new_object: next,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn write_effect_rejects_new_object_identity_change() {
        let current = object(5, Owner::Address(Address::new([0x55; 32])), vec![0x11]);
        let mut next = current.clone();
        next.version = 6;
        next.id = ObjectId::new([0x56; 32]);
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn write_effect_rejects_type_hash_change() {
        let current = object(5, Owner::Address(Address::new([0x57; 32])), vec![0x12]);
        let mut next = current.clone();
        next.version = 6;
        next.type_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0x58; 32]);
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn write_effect_rejects_schema_version_change() {
        let current = object(5, Owner::Address(Address::new([0x59; 32])), vec![0x13]);
        let mut next = current.clone();
        next.version = 6;
        next.schema_version += 1;
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn write_access_rejects_deleted_effect_variant() {
        let current = object(5, Owner::Address(Address::new([0x5a; 32])), vec![0x14]);
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current.clone())],
                &[ObjectEffect::Deleted {
                    id: current.id,
                    version: current.version,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn consume_access_rejects_mutated_effect_variant() {
        let current = object(5, Owner::Address(Address::new([0x5b; 32])), vec![0x15]);
        let mut next = current.clone();
        next.version = 6;
        next.data = vec![0x16];
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Consume, current.clone())],
                &[ObjectEffect::Mutated {
                    previous_version: current.version,
                    new_object: next,
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn consume_effect_rejects_version_mismatch() {
        let current = object(5, Owner::Address(Address::new([0x5c; 32])), vec![0x17]);
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Consume, current.clone())],
                &[ObjectEffect::Deleted {
                    id: current.id,
                    version: current.version.wrapping_sub(1),
                }],
                None,
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn write_effect_rejects_resolver_protocol_version_mismatch() {
        let current = object(5, Owner::Address(Address::new([0x5d; 32])), vec![0x18]);
        let mut next = current.clone();
        next.version = 6;
        next.data = vec![0x19];
        let resolver = resolver();
        let chain_id = ChainId::new("sunrise-mvp").unwrap();
        let mismatched_context = TrustedObjectMutationContext {
            resolver: &resolver,
            chain_id: &chain_id,
            protocol_version: ProtocolVersion::new(2),
            epoch: Epoch::new(0),
            created_checkpoint: 1,
        };
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current)],
                &[ObjectEffect::Mutated {
                    previous_version: 5,
                    new_object: next,
                }],
                Some(&mismatched_context),
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }

    #[test]
    fn write_effect_rejects_per_object_body_over_bound() {
        let current = object(5, Owner::Address(Address::new([0x5e; 32])), Vec::new());
        let mut next = current.clone();
        next.version = 6;
        let empty_length = encode_object(&next).unwrap().len();
        next.data = vec![0; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1 - empty_length];
        let body_length = encode_object(&next).unwrap().len();
        let resolver = resolver();
        let chain_id = ChainId::new("sunrise-mvp").unwrap();
        let context = TrustedObjectMutationContext {
            resolver: &resolver,
            chain_id: &chain_id,
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(0),
            created_checkpoint: 1,
        };
        assert_eq!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current)],
                &[ObjectEffect::Mutated {
                    previous_version: 5,
                    new_object: next.clone(),
                }],
                Some(&context),
                0,
            ),
            Err(NodeCoreError::ObjectBodyTooLarge {
                object_id: next.id,
                actual: body_length,
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            })
        );
    }

    #[test]
    fn write_effect_rejects_aggregate_body_bound_with_already_loaded_bytes() {
        let current = object(5, Owner::Address(Address::new([0x5f; 32])), Vec::new());
        let mut next = current.clone();
        next.version = 6;
        next.data = vec![0; 32];
        let body_length = encode_object(&next).unwrap().len();
        assert!(body_length < MAX_AUTHENTICATED_OBJECT_BODY_BYTES);
        // The loader already accounted for this many old-body bytes; one more
        // small new-body byte must be enough to cross the shared aggregate
        // budget even though the new body alone is far under the per-object
        // bound.
        let loaded_body_bytes = MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES - body_length + 1;
        let resolver = resolver();
        let chain_id = ChainId::new("sunrise-mvp").unwrap();
        let context = TrustedObjectMutationContext {
            resolver: &resolver,
            chain_id: &chain_id,
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(0),
            created_checkpoint: 1,
        };
        assert_eq!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current)],
                &[ObjectEffect::Mutated {
                    previous_version: 5,
                    new_object: next.clone(),
                }],
                Some(&context),
                loaded_body_bytes,
            ),
            Err(NodeCoreError::ObjectBodyTooLarge {
                object_id: next.id,
                actual: loaded_body_bytes + body_length,
                maximum: MAX_AUTHENTICATED_OBJECT_TOTAL_BODY_BYTES,
            })
        );
    }

    #[test]
    fn write_effect_rejects_non_current_head() {
        let current = object(5, Owner::Address(Address::new([0x60; 32])), vec![0x1a]);
        let mut next = current.clone();
        next.version = 6;
        next.data = vec![0x1b];
        let non_current = VerifiedAuthenticatedObject::new(
            AccessMode::Write,
            DurableObjectHead::Absent,
            current.clone(),
        );
        let resolver = resolver();
        let chain_id = ChainId::new("sunrise-mvp").unwrap();
        let context = TrustedObjectMutationContext {
            resolver: &resolver,
            chain_id: &chain_id,
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(0),
            created_checkpoint: 1,
        };
        assert!(matches!(
            translate_authenticated_object_effects(
                &[non_current],
                &[ObjectEffect::Mutated {
                    previous_version: 5,
                    new_object: next,
                }],
                Some(&context),
                0,
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }
}
