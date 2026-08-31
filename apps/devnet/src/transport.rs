//! Bounded, non-panicking local transport for devnet outbox delivery.

use runtime::{RuntimeError, Transport};
use std::{collections::VecDeque, num::NonZeroUsize, sync::Mutex};

/// In-process outbound queue with an explicit message-count bound.
#[derive(Debug)]
pub struct DevnetTransport {
    maximum_messages: NonZeroUsize,
    outbound: Mutex<VecDeque<Vec<u8>>>,
}

impl DevnetTransport {
    /// Creates an empty queue with a fixed non-zero capacity.
    #[must_use]
    pub const fn new(maximum_messages: NonZeroUsize) -> Self {
        Self {
            maximum_messages,
            outbound: Mutex::new(VecDeque::new()),
        }
    }

    /// Returns the configured message-count bound.
    #[must_use]
    pub const fn maximum_messages(&self) -> NonZeroUsize {
        self.maximum_messages
    }
}

impl Transport for DevnetTransport {
    fn send(&self, message: Vec<u8>) -> Result<(), RuntimeError> {
        let mut outbound = self
            .outbound
            .lock()
            .map_err(|_| RuntimeError::TransportUnavailable)?;
        if outbound.len() >= self.maximum_messages.get() {
            return Err(RuntimeError::TransportUnavailable);
        }
        outbound.push_back(message);
        Ok(())
    }

    fn drain_outbound(&self) -> Result<Vec<Vec<u8>>, RuntimeError> {
        let mut outbound = self
            .outbound
            .lock()
            .map_err(|_| RuntimeError::TransportUnavailable)?;
        Ok(outbound.drain(..).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_preserves_order_and_fails_closed_at_capacity() {
        let maximum = NonZeroUsize::new(2).unwrap();
        let transport = DevnetTransport::new(maximum);
        transport.send(vec![1]).unwrap();
        transport.send(vec![2]).unwrap();
        assert_eq!(
            transport.send(vec![3]),
            Err(RuntimeError::TransportUnavailable)
        );
        assert_eq!(transport.drain_outbound().unwrap(), vec![vec![1], vec![2]]);
        assert!(transport.drain_outbound().unwrap().is_empty());
    }
}
