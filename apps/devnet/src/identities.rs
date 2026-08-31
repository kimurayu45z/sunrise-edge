//! Restart-safe operational identities for indexed outbox attempts.

use native_http::{
    IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySource, IndexedOutboxIdentitySourceError,
};
use runtime::{DurableOutboxLeaseId, StorageCorrelationId, WriterFenceGeneration};
use std::sync::atomic::{AtomicU64, Ordering};

/// Allocates unique attempt identities within one persisted boot generation.
#[derive(Debug)]
pub struct DevnetOutboxIdentitySource {
    boot_generation: WriterFenceGeneration,
    sequence: AtomicU64,
}

impl DevnetOutboxIdentitySource {
    /// Starts an identity source for one exclusively claimed boot generation.
    #[must_use]
    pub const fn new(boot_generation: WriterFenceGeneration) -> Self {
        Self {
            boot_generation,
            sequence: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    const fn with_sequence(boot_generation: WriterFenceGeneration, sequence: u64) -> Self {
        Self {
            boot_generation,
            sequence: AtomicU64::new(sequence),
        }
    }

    fn claim_sequence(&self) -> Result<u64, IndexedOutboxIdentitySourceError> {
        let mut current: u64 = self.sequence.load(Ordering::Relaxed);
        loop {
            let next: u64 = current
                .checked_add(1)
                .ok_or(IndexedOutboxIdentitySourceError::Exhausted)?;
            match self.sequence.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(next),
                Err(observed) => current = observed,
            }
        }
    }
}

impl IndexedOutboxIdentitySource for DevnetOutboxIdentitySource {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        let sequence: u64 = self.claim_sequence()?;
        let generation_bytes: [u8; 8] = self.boot_generation.get().to_be_bytes();
        let sequence_bytes: [u8; 8] = sequence.to_be_bytes();

        let mut correlation_bytes: [u8; 16] = [0; 16];
        correlation_bytes[..8].copy_from_slice(&generation_bytes);
        correlation_bytes[8..].copy_from_slice(&sequence_bytes);
        let correlation_id: StorageCorrelationId = StorageCorrelationId::new(correlation_bytes)
            .ok_or(IndexedOutboxIdentitySourceError::Unavailable)?;

        let mut lease_bytes: [u8; 32] = [0; 32];
        lease_bytes[..8].copy_from_slice(&generation_bytes);
        lease_bytes[8..16].copy_from_slice(&sequence_bytes);
        lease_bytes[16..].copy_from_slice(b"sunrise-devnetv1");
        let lease_id: DurableOutboxLeaseId = DurableOutboxLeaseId::new(lease_bytes)
            .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?;

        Ok(IndexedOutboxAttemptIdentity::new(lease_id, correlation_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(value: u64) -> WriterFenceGeneration {
        WriterFenceGeneration::new(value).unwrap()
    }

    #[test]
    fn identities_are_distinct_within_and_across_boots() {
        let first_source = DevnetOutboxIdentitySource::new(generation(2));
        let first = first_source.next_attempt_identity().unwrap();
        let second = first_source.next_attempt_identity().unwrap();
        let next_boot_source = DevnetOutboxIdentitySource::new(generation(3));
        let next_boot = next_boot_source.next_attempt_identity().unwrap();

        assert_ne!(first, second);
        assert_ne!(first, next_boot);
    }

    #[test]
    fn sequence_exhaustion_fails_without_wrapping() {
        let source = DevnetOutboxIdentitySource::with_sequence(generation(2), u64::MAX);
        assert_eq!(
            source.next_attempt_identity(),
            Err(IndexedOutboxIdentitySourceError::Exhausted)
        );
    }
}
