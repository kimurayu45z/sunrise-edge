//! Deterministic fallback state machine for non-transaction devnet events.

use node_core::{
    NodeCoreError, NodeOutput, NodeResponse, NodeResponseStatus, NodeStateAccess,
    NodeStateAccessMode, NodeStateAccessPlan, NodeStateSnapshot, TransactionalNodeStateMachine,
    TransactionalNodeTransition,
};

/// Fixed state key asserted by generic events without mutating application state.
pub const DEVNET_GENERIC_STATE_KEY: &[u8] = b"devnet/generic-events/v1";

/// Rejects generic events deterministically while the preinstalled transaction
/// route handles authenticated asset-account calls separately.
#[derive(Clone, Copy, Debug, Default)]
pub struct DevnetMachine;

impl TransactionalNodeStateMachine for DevnetMachine {
    fn access_plan(
        &self,
        _event: &node_core::NodeEvent,
    ) -> Result<NodeStateAccessPlan, NodeCoreError> {
        let access: NodeStateAccess = NodeStateAccess::new(
            DEVNET_GENERIC_STATE_KEY.to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?;
        NodeStateAccessPlan::new(vec![access])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &node_core::NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let response: NodeResponse =
            NodeResponse::new(event.request_id(), NodeResponseStatus::Rejected, None)?;
        let output: NodeOutput = NodeOutput::new(vec![response], Vec::new())?;
        Ok(TransactionalNodeTransition::read_only(output))
    }
}
