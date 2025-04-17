//! Sans-IO Noise protocol state machine, adapted from noise-psq.

use snow::{TransportState, params::NoiseParams};
use thiserror::Error;
use tracing::trace;

// --- Error Definition ---

/// Errors related to the Noise protocol state machine.
#[derive(Error, Debug)]
pub enum NoiseError {
    #[error("encountered a Noise decryption error")]
    DecryptionError,

    #[error("encountered a Noise Protocol error - {0}")]
    ProtocolError(snow::Error),

    #[error("operation is invalid in the current protocol state")]
    IncorrectStateError,

    #[error("Other Noise-related error: {0}")]
    Other(String),
}

impl From<snow::Error> for NoiseError {
    fn from(err: snow::Error) -> Self {
        match err {
            snow::Error::Decrypt => NoiseError::DecryptionError,
            err => NoiseError::ProtocolError(err),
        }
    }
}

// --- Protocol State and Structs ---

/// Represents the possible states of the Noise protocol machine.
#[derive(Debug)]
pub enum NoiseProtocolState {
    /// The protocol is currently performing the handshake.
    /// Contains the Snow handshake state.
    Handshaking(Box<snow::HandshakeState>),

    /// The handshake is complete, and the protocol is in transport mode.
    /// Contains the Snow transport state.
    Transport(TransportState),

    /// The protocol has encountered an unrecoverable error.
    /// Stores the error description.
    Failed(String),
}

/// The core sans-io Noise protocol state machine.
#[derive(Debug)]
pub struct NoiseProtocol {
    state: NoiseProtocolState,
    // We might need buffers for incoming/outgoing data later if we add internal buffering
    // read_buffer: Vec<u8>,
    // write_buffer: Vec<u8>,
}

/// Represents the outcome of processing received bytes via `read_message`.
#[derive(Debug, PartialEq)]
pub enum ReadResult {
    /// A handshake or transport message was successfully processed, but yielded no application data
    /// and did not complete the handshake.
    NoOp,
    /// A complete application data message was decrypted.
    DecryptedData(Vec<u8>),
    /// The handshake successfully completed during this read operation.
    HandshakeComplete,
    // NOTE: NeedMoreBytes variant removed as read_message expects full frames.
}

// --- Implementation ---

impl NoiseProtocol {
    /// Creates a new `NoiseProtocol` instance in the Handshaking state.
    ///
    /// Takes an initialized `snow::HandshakeState` (e.g., from `snow::Builder`).
    pub fn new(initial_state: snow::HandshakeState) -> Self {
        NoiseProtocol {
            state: NoiseProtocolState::Handshaking(Box::new(initial_state)),
        }
    }

    /// Processes a single, complete incoming Noise message frame.
    ///
    /// Assumes the caller handles buffering and framing to provide one full message.
    /// Returns the result of processing the message.
    pub fn read_message(&mut self, input: &[u8]) -> Result<ReadResult, NoiseError> {
        // Allocate a buffer large enough for the maximum possible Noise message size.
        // TODO: Consider reusing a buffer for efficiency.
        let mut buffer = vec![0u8; 65535]; // Max Noise message size

        match &mut self.state {
            NoiseProtocolState::Handshaking(handshake_state) => {
                match handshake_state.read_message(input, &mut buffer) {
                    Ok(_) => {
                        if handshake_state.is_handshake_finished() {
                            trace!(
                                "Handshake complete, {} transitioning to Transport state",
                                self.role()
                            );

                            // Transition to Transport state.
                            let current_state = std::mem::replace(
                                &mut self.state,
                                // Temporary placeholder needed for mem::replace
                                NoiseProtocolState::Failed(
                                    NoiseError::IncorrectStateError.to_string(),
                                ),
                            );
                            if let NoiseProtocolState::Handshaking(state_to_convert) = current_state
                            {
                                match state_to_convert.into_transport_mode() {
                                    Ok(transport_state) => {
                                        self.state = NoiseProtocolState::Transport(transport_state);
                                        Ok(ReadResult::HandshakeComplete)
                                    }
                                    Err(e) => {
                                        let err = NoiseError::from(e);
                                        self.state = NoiseProtocolState::Failed(err.to_string());
                                        Err(err)
                                    }
                                }
                            } else {
                                // Should be unreachable
                                let err = NoiseError::IncorrectStateError;
                                self.state = NoiseProtocolState::Failed(err.to_string());
                                Err(err)
                            }
                        } else {
                            // Handshake continues
                            Ok(ReadResult::NoOp)
                        }
                    }
                    Err(e) => {
                        let err = NoiseError::from(e);
                        self.state = NoiseProtocolState::Failed(err.to_string());
                        Err(err)
                    }
                }
            }
            NoiseProtocolState::Transport(transport_state) => {
                match transport_state.read_message(input, &mut buffer) {
                    Ok(len) => Ok(ReadResult::DecryptedData(buffer[..len].to_vec())),
                    Err(e) => {
                        let err = NoiseError::from(e);
                        self.state = NoiseProtocolState::Failed(err.to_string());
                        Err(err)
                    }
                }
            }
            NoiseProtocolState::Failed(_) => Err(NoiseError::IncorrectStateError),
        }
    }

    /// Checks if there are pending handshake messages to send.
    ///
    /// If in Handshaking state and it's our turn, generates the message.
    /// Transitions state to Transport if the handshake completes after this message.
    /// Returns `None` if not in Handshaking state or not our turn.
    pub fn get_bytes_to_send(&mut self) -> Option<Result<Vec<u8>, NoiseError>> {
        match &mut self.state {
            NoiseProtocolState::Handshaking(handshake_state) => {
                if handshake_state.is_my_turn() {
                    let mut buffer = vec![0u8; 65535];
                    match handshake_state.write_message(&[], &mut buffer) {
                        // Empty payload for handshake msg
                        Ok(len) => {
                            if handshake_state.is_handshake_finished() {
                                trace!(
                                    "Handshake complete, {} transitioning to Transport state",
                                    self.role()
                                );

                                // Transition to Transport state.
                                let current_state = std::mem::replace(
                                    &mut self.state,
                                    NoiseProtocolState::Failed(
                                        NoiseError::IncorrectStateError.to_string(),
                                    ),
                                );

                                if let NoiseProtocolState::Handshaking(state_to_convert) =
                                    current_state
                                {
                                    match state_to_convert.into_transport_mode() {
                                        Ok(transport_state) => {
                                            self.state =
                                                NoiseProtocolState::Transport(transport_state);
                                            Some(Ok(buffer[..len].to_vec())) // Return final handshake msg
                                        }
                                        Err(e) => {
                                            let err = NoiseError::from(e);
                                            self.state =
                                                NoiseProtocolState::Failed(err.to_string());
                                            Some(Err(err))
                                        }
                                    }
                                } else {
                                    // Should be unreachable
                                    let err = NoiseError::IncorrectStateError;
                                    self.state = NoiseProtocolState::Failed(err.to_string());
                                    Some(Err(err))
                                }
                            } else {
                                // Handshake continues
                                Some(Ok(buffer[..len].to_vec()))
                            }
                        }
                        Err(e) => {
                            let err = NoiseError::from(e);
                            self.state = NoiseProtocolState::Failed(err.to_string());
                            Some(Err(err))
                        }
                    }
                } else {
                    // Not our turn
                    None
                }
            }
            NoiseProtocolState::Transport(_) | NoiseProtocolState::Failed(_) => {
                // No handshake messages to send in these states
                None
            }
        }
    }

    /// Encrypts an application data payload for sending during the Transport phase.
    ///
    /// Returns the ciphertext (payload + 16-byte tag).
    /// Errors if not in Transport state or encryption fails.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match &mut self.state {
            NoiseProtocolState::Transport(transport_state) => {
                let mut buffer = vec![0u8; payload.len() + 16]; // Payload + tag
                match transport_state.write_message(payload, &mut buffer) {
                    Ok(len) => Ok(buffer[..len].to_vec()),
                    Err(e) => {
                        let err = NoiseError::from(e);
                        self.state = NoiseProtocolState::Failed(err.to_string());
                        Err(err)
                    }
                }
            }
            NoiseProtocolState::Handshaking(_) | NoiseProtocolState::Failed(_) => {
                Err(NoiseError::IncorrectStateError)
            }
        }
    }

    /// Returns true if the protocol is in the transport phase (handshake complete).
    pub fn is_transport(&self) -> bool {
        matches!(self.state, NoiseProtocolState::Transport(_))
    }

    /// Returns true if the protocol has failed.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, NoiseProtocolState::Failed(_))
    }

    /// Check if the handshake has finished and the protocol is in transport mode.
    pub fn is_handshake_finished(&self) -> bool {
        matches!(self.state, NoiseProtocolState::Transport(_))
    }

    fn role(&self) -> &'static str {
        match &self.state {
            NoiseProtocolState::Handshaking(hs) => {
                if hs.is_initiator() {
                    "initiator"
                } else {
                    "responder"
                }
            }
            NoiseProtocolState::Transport(t) => {
                if t.is_initiator() {
                    "initiator"
                } else {
                    "responder"
                }
            }
            NoiseProtocolState::Failed(_) => "failed",
        }
    }
}

const DEFAULT_PATTERN_NAME: &str = "Noise_XKpsk3_25519_ChaChaPoly_SHA256";

pub fn create_noise_state_initiator(
    local_private_key: &[u8],
    remote_public_key: &[u8],
    psk: &[u8],
) -> Result<NoiseProtocol, NoiseError> {
    let psk_index = 3;
    let noise_params: NoiseParams = DEFAULT_PATTERN_NAME.parse().unwrap();

    let builder = snow::Builder::new(noise_params.clone());
    // Using dummy remote key as it's not needed for state creation itself
    // In a real scenario, the key would depend on initiator/responder role
    let handshake_state = builder
        .local_private_key(local_private_key)
        .remote_public_key(remote_public_key) // Use own public as dummy remote
        .psk(psk_index, psk)
        .build_initiator()?;
    Ok(NoiseProtocol::new(handshake_state))
}

pub fn create_noise_state_responder(
    local_private_key: &[u8],
    remote_public_key: &[u8],
    psk: &[u8],
) -> Result<NoiseProtocol, NoiseError> {
    let psk_index = 3;
    let noise_params: NoiseParams = DEFAULT_PATTERN_NAME.parse().unwrap();

    let builder = snow::Builder::new(noise_params.clone());
    // Using dummy remote key as it's not needed for state creation itself
    // In a real scenario, the key would depend on initiator/responder role
    let handshake_state = builder
        .local_private_key(local_private_key)
        .remote_public_key(remote_public_key) // Use own public as dummy remote
        .psk(psk_index, psk)
        .build_responder()?;
    Ok(NoiseProtocol::new(handshake_state))
}

#[cfg(test)]
mod test {
    use super::*;

    use tracing::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn test_noise_handshake() {
        crate::test::init_subscriber();

        let initiator_private_key = StaticSecret::random();
        let initiator_public_key = PublicKey::from(&initiator_private_key);

        let responder_private_key = StaticSecret::random();
        let responder_public_key = PublicKey::from(&responder_private_key);

        let psk = [0u8; 32];

        let test_msg_up = "test message up";
        let test_msg_dn = "test message down";

        let mut initiator = create_noise_state_initiator(
            initiator_private_key.as_ref(),
            responder_public_key.as_ref(),
            &psk,
        )
        .unwrap();
        assert!(!initiator.is_transport());
        assert!(!initiator.is_failed());

        let mut responder = create_noise_state_responder(
            responder_private_key.as_ref(),
            initiator_public_key.as_ref(),
            &psk,
        )
        .unwrap();
        assert!(!responder.is_transport());
        assert!(!responder.is_failed());

        // Perform the handshake
        perform_handshake(&mut initiator, &mut responder).expect("handshake failed");

        // Now we can send application data
        let payload_ir_1 = initiator
            .write_message(test_msg_up.as_bytes())
            .expect("Failed to write initiator->responder payload");

        debug!(
            "I -> R ({}B): {:?}",
            payload_ir_1.len(),
            hex::encode(&payload_ir_1)
        );

        let received = responder
            .read_message(&payload_ir_1)
            .expect("Failed to read initiator->responder payload");

        assert_eq!(
            received,
            ReadResult::DecryptedData(test_msg_up.as_bytes().to_vec())
        );

        // Including messages back from responder to initiator
        let payload_ri_1 = responder
            .write_message(&test_msg_dn.as_bytes())
            .expect("Failed to write responder->initiator payload");

        debug!(
            "R -> I ({}B): {:?}",
            payload_ri_1.len(),
            hex::encode(&payload_ri_1)
        );

        let received = initiator
            .read_message(&payload_ri_1)
            .expect("Failed to read responder->initiator payload");

        assert_eq!(
            received,
            ReadResult::DecryptedData(test_msg_dn.as_bytes().to_vec())
        );
    }

    fn perform_handshake(
        initiator: &mut NoiseProtocol,
        responder: &mut NoiseProtocol,
    ) -> Result<(), NoiseError> {
        while !initiator.is_handshake_finished() || !responder.is_handshake_finished() {
            // Handshake messages are exchanged in the following order for the XKpsk3 pattern:
            // -> e, es
            // <- e, ee
            // -> s, se, psk

            if !initiator.is_failed() && !initiator.is_handshake_finished() {
                if let Some(msg) = initiator.get_bytes_to_send() {
                    let msg = msg?;
                    debug!("I -> R ({}B): {:?}", msg.len(), hex::encode(&msg));
                    responder.read_message(&msg)?;
                }
            }

            if !responder.is_failed() && !responder.is_handshake_finished() {
                if let Some(msg) = responder.get_bytes_to_send() {
                    let msg = msg?;
                    debug!("R -> I ({}B): {:?}", msg.len(), hex::encode(&msg));
                    initiator.read_message(&msg)?;
                }
            }
        }

        Ok(())
    }
}
