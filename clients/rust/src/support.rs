//! Small, generic, application-agnostic helpers.
//!
//! Everything here is deliberately generic over any object or protocol
//! value — never devnet or asset-specific — so a consumer such as `apps/cli`
//! never needs a direct dependency on a lower protocol crate just to finish
//! a query/transaction round trip (see `docs/architecture/product-surfaces.md` §44 and
//! `docs/architecture/decisions/0081-0087-cli-first-roadmap.md` DR-0083 and the `apps/cli`
//! MVP boundary in DR-0084).

use node_wire::HttpObjectQueryResult;
use objects::ObjectRef;

/// The only implemented address-binding identifier
/// (`protocol_config::AddressBinding::AddressIsPublicKey::as_u16()`),
/// duplicated here as a plain `u16` constant so a caller can compare it
/// against [`node_wire::HttpContextQueryResult::address_binding_id`]
/// without depending on `protocol-config` directly. This client keeps
/// `protocol-config` as a dev-dependency only (used by `stable_vectors` to
/// pin this constant against the real value), so the two cannot silently
/// drift out of sync.
pub const ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID: u16 = 1;

/// The only implemented transaction-authentication profile identifier
/// (`protocol_config::ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID`), duplicated
/// here as a plain `u16` constant so a caller can compare it against
/// [`node_wire::HttpContextQueryResult::transaction_auth_profile_id`]
/// without depending on `protocol-config` directly. A committed profile id
/// is a protocol identifier, not an arbitrary non-zero label: a context
/// declaring any other id is not authenticating transactions the way this
/// client's signer and [`crate::transaction::PreparedTransaction`] assume.
/// `protocol-config` stays a dev-dependency only; a dedicated test pins this
/// constant against the real value so the two cannot silently drift.
pub const ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID: u16 = 1;

/// Extracts the exact `ObjectRef` (identifier, current version, digest)
/// from a `CurrentInline` object query result.
///
/// Returns `None` for every other status (absent, tombstoned, or
/// blob-backed): only a currently live inline object has a reference safe
/// to declare `Write`/`Consume` access to in a new transaction. This makes
/// no claim about the object's type, owner, or body — that judgment belongs
/// to the caller.
#[must_use]
pub fn current_inline_object_ref(result: &HttpObjectQueryResult) -> Option<ObjectRef> {
    match result {
        HttpObjectQueryResult::CurrentInline {
            object_id,
            object_version,
            digest,
            ..
        } => Some(ObjectRef {
            id: *object_id,
            version: object_version.get(),
            digest: *digest,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objects::ObjectId;
    use protocol_types::{Digest32, HashAlgorithmId};
    use runtime::{DurableObjectVersion, ObjectHeadRevision};

    #[test]
    fn extracts_a_ref_only_for_current_inline() {
        let object_id = ObjectId::new([0x09; 32]);
        let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x0A; 32]);
        let current = HttpObjectQueryResult::CurrentInline {
            object_id,
            head_revision: ObjectHeadRevision::new(1).unwrap(),
            object_version: DurableObjectVersion::new(3).unwrap(),
            digest,
            canonical_object_bytes: vec![1, 2, 3],
        };
        assert_eq!(
            current_inline_object_ref(&current),
            Some(ObjectRef {
                id: object_id,
                version: 3,
                digest,
            })
        );

        assert_eq!(
            current_inline_object_ref(&HttpObjectQueryResult::Absent { object_id }),
            None
        );
    }

    #[test]
    fn address_binding_id_matches_protocol_config() {
        assert_eq!(
            ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
            protocol_config::AddressBinding::AddressIsPublicKey.as_u16()
        );
    }

    #[test]
    fn auth_profile_id_matches_protocol_config() {
        assert_eq!(
            ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
            protocol_config::ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID
        );
    }
}
