//! Trusted pure fee-effect composition capability.
//!
//! Node-core cannot decode an application's object body (see `AGENTS.md`'s
//! crate-boundary rules): it never learns what an `AssetAccount`, or any
//! other application type, actually looks like. Charging a transaction fee
//! from a settled amount therefore requires one narrow, explicitly trusted
//! extension point supplied by node composition, exactly like
//! [`crate::PreinstalledModuleCatalog`] and the WASM execution engine: a pure
//! function from opaque body bytes to opaque body bytes. It is never
//! reachable from request bytes, never performs I/O, and cannot express an
//! owner change, a version change, a type/schema change, an effect on a
//! third object, or object creation/deletion — node-core independently
//! rebuilds every [`execution::ObjectEffect::Mutated`] value from its own
//! verified, loaded objects and revalidates it through the unchanged
//! [`crate::authenticated_object_effects`] translation.

use core::fmt;
use std::error::Error;

use fees::{FeeAssetRegistry, GasSchedule};
use objects::ObjectId;
use standard_assets::AssetId;

/// Deterministic settlement input for one fee charge over two asset-account
/// bodies: the payer (declared, sender-owned) and the trusted composition
/// treasury.
#[derive(Clone, Copy, Debug)]
pub struct FeeChargeRequest<'a> {
    /// Fee asset the sender authorized.
    pub asset_id: AssetId,
    /// Settled charge amount in asset units. Always non-zero: node-core
    /// never calls the composer for a zero-amount charge.
    pub amount: fees::Amount,
    /// Effective payer body: the application's post-execution body when the
    /// application already mutated it, otherwise the loaded pre-execution
    /// body.
    pub payer_body: &'a [u8],
    /// Effective treasury body. The preinstalled module never sees the
    /// treasury object, so this is always the loaded pre-execution body.
    pub treasury_body: &'a [u8],
}

/// The composer's pure output: the new payer and treasury bodies after
/// settling exactly one fee charge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeChargeBodies {
    /// New payer body after the charge is debited.
    pub payer_body: Vec<u8>,
    /// New treasury body after the charge is credited.
    pub treasury_body: Vec<u8>,
}

/// Errors a [`FeeEffectComposer`] may return.
///
/// These are the only failure modes node-core can attribute to the pure
/// composition step; every identity/version/owner/type/schema/size invariant
/// is independently re-checked by node-core itself and reported through
/// `NodeCoreError` instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeCompositionError {
    /// A supplied body did not decode as the expected application type.
    MalformedBody,
    /// The body's own asset identifier disagreed with the requested charge.
    AssetMismatch,
    /// The payer body's balance is insufficient to cover the settled amount.
    InsufficientBalance,
    /// Checked arithmetic overflowed while composing the new bodies.
    Overflow,
}

impl fmt::Display for FeeCompositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedBody => f.write_str("fee composer received a malformed body"),
            Self::AssetMismatch => {
                f.write_str("fee composer body disagrees with the charged asset")
            }
            Self::InsufficientBalance => {
                f.write_str("fee composer payer balance is insufficient for the settled amount")
            }
            Self::Overflow => f.write_str("fee composer arithmetic overflowed"),
        }
    }
}

impl Error for FeeCompositionError {}

/// Opaque, deterministic fee settlement over two asset-account bodies.
///
/// Trusted node composition supplies the only implementation, exactly like
/// [`crate::PreinstalledModuleCatalog`]. It is never reachable from request
/// bytes and node-core never uses it to interpret application state for any
/// other purpose.
pub trait FeeEffectComposer: fmt::Debug + Send + Sync {
    /// Computes the new payer and treasury bodies for one settled fee charge.
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError>;
}

/// Trusted node composition's fee-charging capability for one preinstalled-
/// WASM entrypoint invocation.
///
/// `treasury_object_id` is composition, never request input: the sender's
/// signed transaction can never redirect where a fee is credited.
pub struct PreinstalledFeeComposition<'a> {
    /// The unique object a fee charge credits. Node-core authorizes this
    /// exact id as the final declared `Write` access and hides it from the
    /// preinstalled module's execution inputs.
    pub treasury_object_id: ObjectId,
    /// The pure composer used to settle a charge once node-core has already
    /// validated admission and computed the exact amount.
    pub composer: &'a dyn FeeEffectComposer,
}

impl fmt::Debug for PreinstalledFeeComposition<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreinstalledFeeComposition")
            .field("treasury_object_id", &self.treasury_object_id)
            .field("composer", &self.composer)
            .finish()
    }
}

impl<'a> PreinstalledFeeComposition<'a> {
    /// Creates a trusted fee-charging capability.
    #[must_use]
    pub const fn new(treasury_object_id: ObjectId, composer: &'a dyn FeeEffectComposer) -> Self {
        Self {
            treasury_object_id,
            composer,
        }
    }
}

/// The committed `GasSchedule`/`FeeAssetRegistry` captured from authenticated
/// `ProtocolConfig` at the same point [`crate::AuthenticatedSubmitTransaction`]
/// captures its committed system-module record.
///
/// Cloned from committed configuration, never from request bytes, so a
/// caller cannot authenticate under one committed schedule and later settle
/// a fee against a different one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedFeePolicy {
    /// Committed deterministic fee price schedule.
    pub gas_schedule: GasSchedule,
    /// Committed set of assets usable for transaction fees.
    pub fee_assets: FeeAssetRegistry,
}

/// A committed [`GasSchedule`] shape the preinstalled-WASM fee-aware path
/// cannot safely charge.
///
/// The preinstalled-WASM machine only ever measures `execution_units`: every
/// `fees::FeeUsage` it builds leaves `state_read_units`, `state_write_units`,
/// `storage_units`, and `system_module_units` at their default zero, so a
/// non-zero `read_price`/`write_price`/`storage_price`/`system_module_price`
/// in the committed schedule can never actually be charged. That is not a
/// harmless unused field: `fees::calculate_fee` would silently multiply it by
/// zero usage and drop it from the total, which is exactly the "silently
/// downgrade an unsupported value" pattern `AGENTS.md` forbids. Separately, a
/// non-zero `execution_price` with a zero `base_fee` lets a legitimate
/// zero-`gas_used` success settle to exactly zero even though worst-case
/// admission at `gas_limit` already required a treasury `Write` — a shape
/// that only [`crate::NodeCoreError::FeeAmountZero`] would otherwise catch,
/// and only after the engine has already run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GasScheduleShapeFault {
    /// A non-zero price was committed for a resource category this path
    /// never measures.
    UnmeasuredCategoryPriced,
    /// `execution_price` is non-zero while `base_fee` is zero.
    ZeroBaseFeeWithExecutionPrice,
}

impl fmt::Display for GasScheduleShapeFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmeasuredCategoryPriced => f.write_str(
                "committed gas schedule prices a read/write/storage/system-module category the preinstalled-WASM fee-aware path never measures",
            ),
            Self::ZeroBaseFeeWithExecutionPrice => f.write_str(
                "committed gas schedule has a zero base_fee with a non-zero execution_price",
            ),
        }
    }
}

impl Error for GasScheduleShapeFault {}

/// Rejects a committed [`GasSchedule`] whose shape the preinstalled-WASM
/// fee-aware path cannot safely charge (see [`GasScheduleShapeFault`]).
///
/// The all-zero [`GasSchedule::genesis`] and the current devnet
/// `base_fee`/`execution_price`-only schedule both pass.
pub fn validate_gas_schedule_shape(schedule: &GasSchedule) -> Result<(), GasScheduleShapeFault> {
    if schedule.read_price != 0
        || schedule.write_price != 0
        || schedule.storage_price != 0
        || schedule.system_module_price != 0
    {
        return Err(GasScheduleShapeFault::UnmeasuredCategoryPriced);
    }
    if schedule.base_fee == 0 && schedule.execution_price != 0 {
        return Err(GasScheduleShapeFault::ZeroBaseFeeWithExecutionPrice);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct EchoComposer;

    impl FeeEffectComposer for EchoComposer {
        fn compose_fee_charge(
            &self,
            request: &FeeChargeRequest<'_>,
        ) -> Result<FeeChargeBodies, FeeCompositionError> {
            Ok(FeeChargeBodies {
                payer_body: request.payer_body.to_vec(),
                treasury_body: request.treasury_body.to_vec(),
            })
        }
    }

    #[test]
    fn composer_trait_object_is_object_safe_and_callable() {
        let composer = EchoComposer;
        let dynamic: &dyn FeeEffectComposer = &composer;
        let request = FeeChargeRequest {
            asset_id: AssetId::new([0x11; 32]),
            amount: fees::Amount::new(5),
            payer_body: &[1, 2, 3],
            treasury_body: &[4, 5, 6],
        };
        let bodies = dynamic.compose_fee_charge(&request).unwrap();
        assert_eq!(bodies.payer_body, vec![1, 2, 3]);
        assert_eq!(bodies.treasury_body, vec![4, 5, 6]);
    }

    #[test]
    fn composition_debug_does_not_panic() {
        let composer = EchoComposer;
        let composition = PreinstalledFeeComposition::new(ObjectId::new([0x22; 32]), &composer);
        let rendered = format!("{composition:?}");
        assert!(rendered.contains("PreinstalledFeeComposition"));
    }

    #[test]
    fn fee_composition_error_display_is_stable_and_non_empty() {
        for error in [
            FeeCompositionError::MalformedBody,
            FeeCompositionError::AssetMismatch,
            FeeCompositionError::InsufficientBalance,
            FeeCompositionError::Overflow,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn gas_schedule_shape_accepts_genesis_and_current_devnet_shape() {
        assert_eq!(validate_gas_schedule_shape(&GasSchedule::genesis()), Ok(()));
        assert_eq!(
            validate_gas_schedule_shape(&GasSchedule {
                base_fee: 1,
                execution_price: 1,
                read_price: 0,
                write_price: 0,
                storage_price: 0,
                system_module_price: 0,
            }),
            Ok(())
        );
    }

    #[test]
    fn gas_schedule_shape_rejects_any_unmeasured_category_price() {
        let base = GasSchedule::genesis();
        for schedule in [
            GasSchedule {
                read_price: 1,
                ..base.clone()
            },
            GasSchedule {
                write_price: 1,
                ..base.clone()
            },
            GasSchedule {
                storage_price: 1,
                ..base.clone()
            },
            GasSchedule {
                system_module_price: 1,
                ..base.clone()
            },
        ] {
            assert_eq!(
                validate_gas_schedule_shape(&schedule),
                Err(GasScheduleShapeFault::UnmeasuredCategoryPriced)
            );
        }
    }

    #[test]
    fn gas_schedule_shape_rejects_zero_base_fee_with_nonzero_execution_price() {
        let schedule = GasSchedule {
            base_fee: 0,
            execution_price: 1,
            ..GasSchedule::genesis()
        };
        assert_eq!(
            validate_gas_schedule_shape(&schedule),
            Err(GasScheduleShapeFault::ZeroBaseFeeWithExecutionPrice)
        );
    }

    #[test]
    fn gas_schedule_shape_accepts_nonzero_base_fee_with_zero_execution_price() {
        let schedule = GasSchedule {
            base_fee: 1,
            execution_price: 0,
            ..GasSchedule::genesis()
        };
        assert_eq!(validate_gas_schedule_shape(&schedule), Ok(()));
    }

    #[test]
    fn gas_schedule_shape_fault_display_is_stable_and_non_empty() {
        for fault in [
            GasScheduleShapeFault::UnmeasuredCategoryPriced,
            GasScheduleShapeFault::ZeroBaseFeeWithExecutionPrice,
        ] {
            assert!(!fault.to_string().is_empty());
        }
    }
}
