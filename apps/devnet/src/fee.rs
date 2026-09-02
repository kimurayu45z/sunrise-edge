//! The local devnet's trusted [`node_core::FeeEffectComposer`] implementation.
//!
//! Settles one fee charge over two ordinary
//! [`crate::asset_account::AssetAccount`] bodies using the same strict codec
//! the preinstalled module's host ABI relies on. This is trusted node
//! composition, never reachable from request bytes: node-core independently
//! rebuilds identity/version/owner/type/schema for both mutated objects and
//! only asks this composer for the new balances.

use crate::asset_account::{AssetAccount, decode_asset_account, encode_asset_account};
use node_core::{FeeChargeBodies, FeeChargeRequest, FeeCompositionError, FeeEffectComposer};

/// Settles a fee charge by debiting the payer and crediting the treasury,
/// both ordinary [`AssetAccount`] bodies for the same [`fees::AssetId`].
#[derive(Debug, Default, Clone, Copy)]
pub struct AssetAccountFeeComposer;

impl FeeEffectComposer for AssetAccountFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        let mut payer: AssetAccount = decode_asset_account(request.payer_body)
            .map_err(|_| FeeCompositionError::MalformedBody)?;
        let mut treasury: AssetAccount = decode_asset_account(request.treasury_body)
            .map_err(|_| FeeCompositionError::MalformedBody)?;

        if payer.asset_id != request.asset_id || treasury.asset_id != request.asset_id {
            return Err(FeeCompositionError::AssetMismatch);
        }

        let amount: u64 = request.amount.get();
        payer.balance = payer
            .balance
            .checked_sub(amount)
            .ok_or(FeeCompositionError::InsufficientBalance)?;
        payer.sequence = payer
            .sequence
            .checked_add(1)
            .ok_or(FeeCompositionError::Overflow)?;

        treasury.balance = treasury
            .balance
            .checked_add(amount)
            .ok_or(FeeCompositionError::Overflow)?;
        treasury.sequence = treasury
            .sequence
            .checked_add(1)
            .ok_or(FeeCompositionError::Overflow)?;

        let payer_body: Vec<u8> =
            encode_asset_account(&payer).map_err(|_| FeeCompositionError::MalformedBody)?;
        let treasury_body: Vec<u8> =
            encode_asset_account(&treasury).map_err(|_| FeeCompositionError::MalformedBody)?;

        Ok(FeeChargeBodies {
            payer_body,
            treasury_body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_account::DEVNET_ASSET_ID;
    use fees::{Amount, AssetId};

    fn request<'a>(
        amount: u64,
        payer_body: &'a [u8],
        treasury_body: &'a [u8],
    ) -> FeeChargeRequest<'a> {
        FeeChargeRequest {
            asset_id: DEVNET_ASSET_ID,
            amount: Amount::new(amount),
            payer_body,
            treasury_body,
        }
    }

    fn encoded(account: AssetAccount) -> Vec<u8> {
        encode_asset_account(&account).expect("valid test account")
    }

    #[test]
    fn charges_exact_amount_and_bumps_both_sequences() {
        let payer: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 1_000, 3));
        let treasury: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 0, 9));

        let bodies: FeeChargeBodies = AssetAccountFeeComposer
            .compose_fee_charge(&request(40, &payer, &treasury))
            .expect("sufficient balance settles");

        let new_payer: AssetAccount = decode_asset_account(&bodies.payer_body).unwrap();
        let new_treasury: AssetAccount = decode_asset_account(&bodies.treasury_body).unwrap();
        assert_eq!(new_payer, AssetAccount::new(DEVNET_ASSET_ID, 960, 4));
        assert_eq!(new_treasury, AssetAccount::new(DEVNET_ASSET_ID, 40, 10));
    }

    #[test]
    fn charge_conserves_total_balance_across_both_accounts() {
        let payer_before = AssetAccount::new(DEVNET_ASSET_ID, 5_000, 0);
        let treasury_before = AssetAccount::new(DEVNET_ASSET_ID, 200, 0);
        let payer: Vec<u8> = encoded(payer_before);
        let treasury: Vec<u8> = encoded(treasury_before);

        let bodies: FeeChargeBodies = AssetAccountFeeComposer
            .compose_fee_charge(&request(75, &payer, &treasury))
            .expect("sufficient balance settles");

        let new_payer: AssetAccount = decode_asset_account(&bodies.payer_body).unwrap();
        let new_treasury: AssetAccount = decode_asset_account(&bodies.treasury_body).unwrap();
        let payer_delta: i128 = i128::from(new_payer.balance) - i128::from(payer_before.balance);
        let treasury_delta: i128 =
            i128::from(new_treasury.balance) - i128::from(treasury_before.balance);
        assert_eq!(payer_delta, -treasury_delta);
        assert_eq!(payer_delta, -75);
    }

    #[test]
    fn malformed_payer_body_is_rejected() {
        let treasury: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 0, 0));
        let malformed: [u8; 4] = [0xFF, 0x00, 0x11, 0x22];

        let error = AssetAccountFeeComposer
            .compose_fee_charge(&request(1, &malformed, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::MalformedBody);
    }

    #[test]
    fn malformed_treasury_body_is_rejected() {
        let payer: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 1_000, 0));
        let malformed: [u8; 4] = [0xFF, 0x00, 0x11, 0x22];

        let error = AssetAccountFeeComposer
            .compose_fee_charge(&request(1, &payer, &malformed))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::MalformedBody);
    }

    #[test]
    fn wrong_payer_asset_id_is_rejected() {
        let other_asset: AssetId = AssetId::new([0x42; 32]);
        let payer: Vec<u8> = encoded(AssetAccount::new(other_asset, 1_000, 0));
        let treasury: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 0, 0));

        let error = AssetAccountFeeComposer
            .compose_fee_charge(&request(1, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::AssetMismatch);
    }

    #[test]
    fn wrong_treasury_asset_id_is_rejected() {
        let other_asset: AssetId = AssetId::new([0x42; 32]);
        let payer: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 1_000, 0));
        let treasury: Vec<u8> = encoded(AssetAccount::new(other_asset, 0, 0));

        let error = AssetAccountFeeComposer
            .compose_fee_charge(&request(1, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::AssetMismatch);
    }

    #[test]
    fn insufficient_balance_is_rejected_without_mutating_treasury() {
        let payer: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 10, 0));
        let treasury: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 0, 0));

        let error = AssetAccountFeeComposer
            .compose_fee_charge(&request(11, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::InsufficientBalance);
    }

    #[test]
    fn exact_balance_settles_to_zero() {
        let payer: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 10, 0));
        let treasury: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 0, 0));

        let bodies: FeeChargeBodies = AssetAccountFeeComposer
            .compose_fee_charge(&request(10, &payer, &treasury))
            .expect("exact balance settles");
        let new_payer: AssetAccount = decode_asset_account(&bodies.payer_body).unwrap();
        assert_eq!(new_payer.balance, 0);
    }

    #[test]
    fn treasury_balance_overflow_is_rejected() {
        let payer: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, u64::MAX, 0));
        let treasury: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, u64::MAX - 1, 0));

        let error = AssetAccountFeeComposer
            .compose_fee_charge(&request(5, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::Overflow);
    }

    #[test]
    fn payer_sequence_overflow_is_rejected() {
        let payer: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 1_000, u64::MAX));
        let treasury: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 0, 0));

        let error = AssetAccountFeeComposer
            .compose_fee_charge(&request(1, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::Overflow);
    }

    #[test]
    fn treasury_sequence_overflow_is_rejected() {
        let payer: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 1_000, 0));
        let treasury: Vec<u8> = encoded(AssetAccount::new(DEVNET_ASSET_ID, 0, u64::MAX));

        let error = AssetAccountFeeComposer
            .compose_fee_charge(&request(1, &payer, &treasury))
            .unwrap_err();
        assert_eq!(error, FeeCompositionError::Overflow);
    }
}
