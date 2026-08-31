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
    pub(super) const fn new(mode: AccessMode, head: DurableObjectHead, object: Object) -> Self {
        Self { mode, head, object }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct LoadedAuthenticatedObjects {
    reads: Vec<DurableObjectHeadRead>,
    verified: Vec<VerifiedAuthenticatedObject>,
}

impl LoadedAuthenticatedObjects {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            reads: Vec::with_capacity(capacity),
            verified: Vec::with_capacity(capacity),
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

    pub(super) fn into_reads(self) -> Vec<DurableObjectHeadRead> {
        self.reads
    }
}

/// Trusted context required only when execution creates a new immutable version.
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
pub(super) fn translate_authenticated_object_effects(
    verified: &[VerifiedAuthenticatedObject],
    effects: &[ObjectEffect],
    context: Option<&TrustedObjectMutationContext<'_>>,
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
    let mut represented_body_bytes: usize = 0;
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
            ),
            Err(NodeCoreError::UndeclaredObjectEffect { .. })
        ));
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Consume, first.clone())],
                &[duplicate_effect.clone(), duplicate_effect],
                None,
            ),
            Err(NodeCoreError::DuplicateObjectEffect { .. })
        ));
        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Read, first)],
                &[ObjectEffect::Created(undeclared)],
                None,
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
            translate_authenticated_object_effects(&[], &excessive_effects, None),
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
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));

        assert!(matches!(
            translate_authenticated_object_effects(
                &[verified(AccessMode::Write, current)],
                &[],
                Some(&context),
            ),
            Err(NodeCoreError::ObjectEffectMismatch { .. })
        ));
    }
}
