use std::fmt::Debug;

use libcrux_psq::{
    cred::{Authenticator, NoAuth},
    psk_registration::{Initiator, InitiatorMsg, RegisteredPsk, Responder, ResponderMsg},
    traits::{Decode, Encode, PSQ},
};
use libcrux_traits::kem::KEM;
use rand::CryptoRng;
use thiserror::Error;
use tracing::*;

use std::time::Duration;

const DEFAULT_PSK_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Error)]
pub enum PsqError {
    #[error("operation not allowed in current state")]
    IncorrectStateError,

    #[error("an error occurred in the underlying psq library: {0:?}")]
    CryptoFailure(libcrux_psq::Error),

    #[error("authentication failure: {0:?}")]
    AuthFailure(libcrux_psq::Error),

    #[error("missing required field")]
    RequiredFieldMissing,
}

impl From<libcrux_psq::Error> for PsqError {
    fn from(err: libcrux_psq::Error) -> Self {
        match err {
            libcrux_psq::Error::CredError => PsqError::AuthFailure(err),
            _ => PsqError::CryptoFailure(err),
        }
    }
}

pub struct PsqBuilder<'builder, C, T>
where
    C: Authenticator,
    T: PSQ,
{
    // Required by all
    pub local_decapsulation_key: Option<&'builder <T::InnerKEM as KEM>::DecapsulationKey>,
    pub local_encapsulation_key: Option<&'builder <T::InnerKEM as KEM>::EncapsulationKey>,

    // Used  by all
    pub ctx: &'builder str,
    pub psk_ttl: Option<Duration>, // default 1 hour

    // responder only
    pub handle: &'builder str,

    // initiator only
    pub remote_public_key: Option<&'builder <T::InnerKEM as KEM>::EncapsulationKey>,

    // used when to authenticate self to peer
    pub local_ident_key: Option<&'builder C::SigningKey>,
    pub local_verif_key: Option<&'builder C::Credential>,

    // used when authenticating peer
    pub remote_ident_cert: Option<&'builder C::Certificate>,
}

impl<'b, T> PsqBuilder<'b, NoAuth, T>
where
    T: PSQ,
{
    pub fn new() -> Self {
        Self {
            handle: "",
            ctx: "",
            psk_ttl: None,
            remote_public_key: None,
            local_decapsulation_key: None,
            local_encapsulation_key: None,

            // Authentication
            remote_ident_cert: Some(&[0u8; 0]),
            local_ident_key: Some(&[0u8; 0]),
            local_verif_key: Some(&[0u8; 0]),
        }
    }
}

impl<'b, C, T> PsqBuilder<'b, C, T>
where
    C: Authenticator,
    T: PSQ,
{
    pub fn with_handle(mut self, handle: &'b str) -> Self {
        self.handle = handle;
        self
    }

    pub fn with_psk_ttl(mut self, psk_ttl: Duration) -> Self {
        self.psk_ttl = Some(psk_ttl);
        self
    }

    pub fn with_ctx(mut self, ctx: &'b str) -> Self {
        self.ctx = ctx;
        self
    }

    pub fn remote_public_key(
        mut self,
        remote_public_key: &'b <T::InnerKEM as KEM>::EncapsulationKey,
    ) -> Self {
        self.remote_public_key = Some(remote_public_key);
        self
    }

    pub fn initiator_cert<A: Authenticator>(
        self,
        remote_ident_cert: &'b A::Certificate,
    ) -> PsqBuilder<'b, A, T> {
        PsqBuilder {
            local_decapsulation_key: self.local_decapsulation_key,
            local_encapsulation_key: self.local_encapsulation_key,
            ctx: self.ctx,
            psk_ttl: self.psk_ttl,
            handle: self.handle,
            remote_public_key: self.remote_public_key,

            local_ident_key: None,
            local_verif_key: None,
            remote_ident_cert: Some(remote_ident_cert),
        }
    }

    pub fn initiator_auth<A: Authenticator>(
        self,
        local_ident_key: &'b A::SigningKey,
        local_verif_key: &'b A::Credential,
    ) -> PsqBuilder<'b, A, T> {
        PsqBuilder {
            local_decapsulation_key: self.local_decapsulation_key,
            local_encapsulation_key: self.local_encapsulation_key,
            ctx: self.ctx,
            psk_ttl: self.psk_ttl,
            handle: self.handle,
            remote_public_key: self.remote_public_key,

            local_ident_key: Some(local_ident_key),
            local_verif_key: Some(local_verif_key),
            remote_ident_cert: None,
        }
    }

    pub fn local_key_pair(
        mut self,
        local_decapsulation_key: &'b <T::InnerKEM as KEM>::DecapsulationKey,
        local_encapsulation_key: &'b <T::InnerKEM as KEM>::EncapsulationKey,
    ) -> Self {
        self.local_decapsulation_key = Some(local_decapsulation_key);
        self.local_encapsulation_key = Some(local_encapsulation_key);
        self
    }

    pub fn build_initiator(self) -> Result<PsqProtocol<'b, C, T>, PsqError> {
        if !self.handle.is_empty() {
            warn!("Handle set, but not used by the initiator");
        }
        if self.remote_ident_cert.is_some() {
            warn!("Remote Auth Certificate set, but not used by the initiator");
        }
        if self.remote_public_key.is_none() {
            warn!("Remote Public Key not set, but required by the initiator");
            return Err(PsqError::RequiredFieldMissing);
        }
        if self.local_ident_key.is_none() || self.local_verif_key.is_none() {
            warn!(
                "Local Auth Identity Key and/or Local Auth Verification Key not set, but required by the initiator"
            );
            return Err(PsqError::RequiredFieldMissing);
        }

        Ok(PsqProtocol {
            initiator: true,
            state: State::InitiatorAwaitingSend,

            psq: Psq::Initiator(self.remote_public_key.unwrap()),
            ctx: self.ctx,
            psk_ttl: self.psk_ttl,
            handle: self.handle,

            auth: Auth::Initiator(self.local_ident_key.unwrap(), self.local_verif_key.unwrap()),
        })
    }

    pub fn build_responder(self) -> Result<PsqProtocol<'b, C, T>, PsqError> {
        if self.remote_public_key.is_some() {
            warn!("Remote Public Key set, but not used by the responder");
        }
        if self.local_ident_key.is_some() {
            warn!("Local Auth Identity Key set, but not used by the responder");
        }
        if self.remote_public_key.is_some() {
            warn!("Local Auth Verification Key set, but not used by the responder");
        }
        if self.remote_ident_cert.is_none() {
            warn!("Remote Auth Certificate not set, but required by the responder");
            return Err(PsqError::RequiredFieldMissing);
        }

        Ok(PsqProtocol {
            initiator: false,
            state: State::ResponderAwaitingReceive,

            psq: Psq::Responder(
                self.local_decapsulation_key.unwrap(),
                self.local_encapsulation_key.unwrap(),
            ),
            ctx: self.ctx,
            psk_ttl: self.psk_ttl,
            handle: self.handle,

            auth: Auth::Responder(self.remote_ident_cert.unwrap()),
        })
    }
}

enum Auth<'auth, C: Authenticator> {
    Initiator(&'auth C::SigningKey, &'auth C::Credential),
    Responder(&'auth C::Certificate),
}

enum Psq<'psq, T: PSQ> {
    Initiator(&'psq <T::InnerKEM as KEM>::EncapsulationKey),
    Responder(
        &'psq <T::InnerKEM as KEM>::DecapsulationKey,
        &'psq <T::InnerKEM as KEM>::EncapsulationKey,
    ),
}

enum State {
    InitiatorAwaitingReceive(libcrux_psq::psk_registration::Initiator),
    ResponderAwaitingReceive,
    InitiatorAwaitingSend,
    ResponderAwaitingSend(Vec<u8>, RegisteredPsk),
    Finished(RegisteredPsk),
    Failed,
}

// manual impl as inner type doesn't implement Debug
impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::ResponderAwaitingReceive => write!(f, "AwaitingReceive"),
            State::InitiatorAwaitingReceive(_) => write!(f, "AwaitingReceive"),
            State::InitiatorAwaitingSend => write!(f, "AwaitingSend"),
            State::ResponderAwaitingSend(_, _) => write!(f, "AwaitingSend"),
            State::Finished(_) => write!(f, "Finished"),
            State::Failed => write!(f, "Failed"),
        }
    }
}

pub struct PsqProtocol<'proto, C, T>
where
    C: Authenticator,
    T: PSQ,
{
    initiator: bool,
    state: State,

    psq: Psq<'proto, T>,

    // Used  by all
    ctx: &'proto str,
    psk_ttl: Option<Duration>, // default 1 hour

    // responder only
    handle: &'proto str,

    auth: Auth<'proto, C>,
}

impl<'p, T> PsqProtocol<'p, NoAuth, T>
where
    T: PSQ,
    InitiatorMsg<<T as PSQ>::InnerKEM>: Decode,
{
    pub fn builder() -> PsqBuilder<'p, NoAuth, T> {
        PsqBuilder::new()
    }
}

impl<'p, C, T> PsqProtocol<'p, C, T>
where
    C: Authenticator,
    T: PSQ,
    InitiatorMsg<<T as PSQ>::InnerKEM>: Decode,
{
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// Reads a message from `input` attempting to step the handshake state forward.
    ///
    /// Returns the size of the payload written to `payload`.
    ///
    /// # Errors
    ///
    /// Will result in `Error::Decrypt` if the contents couldn't be decrypted and/or the
    /// authentication tag didn't verify.
    ///
    /// Will result in `StateProblem::Exhausted` if the max nonce count overflows.
    pub fn read_message(&mut self, message: &[u8]) -> Result<usize, PsqError> {
        match &self.state {
            State::InitiatorAwaitingReceive(state) => {
                if !self.is_initiator() {
                    // this shouldn't be possible
                    self.state = State::Failed;
                    return Err(PsqError::IncorrectStateError);
                }

                let (responder_msg, n) = ResponderMsg::decode(message)?;

                trace!("received valid responder msg");

                // Finish the handshake
                let psk = state.complete_handshake(&responder_msg)?;

                self.state = State::Finished(psk);

                Ok(n)
            }
            State::ResponderAwaitingReceive => {
                if self.is_initiator() {
                    // this shouldn't be possible
                    self.state = State::Failed;
                    return Err(PsqError::IncorrectStateError);
                }

                let (initiator_msg, n) = InitiatorMsg::<T::InnerKEM>::decode(message)
                    .inspect_err(|e| error!("decode failure: {e:?}"))?;

                let initiator_cert = match &self.auth {
                    Auth::Initiator(_, _) => {
                        // This should be impossible to reach
                        return Err(PsqError::IncorrectStateError);
                    }
                    Auth::Responder(cert) => cert,
                };

                let (local_decapsulation_key, local_encapsulation_key) = match &self.psq {
                    Psq::Responder(dk, ek) => (dk, ek),
                    Psq::Initiator(_) => {
                        // This should be impossible to reach
                        return Err(PsqError::IncorrectStateError);
                    }
                };

                let (psk, msg) = Responder::send::<C, T>(
                    self.handle.as_bytes(),
                    self.psk_ttl.unwrap_or(DEFAULT_PSK_TTL),
                    self.ctx.as_bytes(),
                    &local_encapsulation_key,
                    &local_decapsulation_key,
                    initiator_cert,
                    &initiator_msg,
                )
                .inspect_err(|e| error!("handshake failure: {e:?}"))?;

                trace!("received valid initiator msg");

                // Send the message back.
                let encoded_msg = msg.encode();
                self.state = State::ResponderAwaitingSend(encoded_msg, psk);
                Ok(n)
            }
            _ => {
                self.state = State::Failed;
                Err(PsqError::IncorrectStateError)
            }
        }
    }

    pub fn get_bytes_to_send<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        buffer: &mut [u8],
    ) -> Result<usize, PsqError> {
        let (result, next_state) = match &self.state {
            State::InitiatorAwaitingSend => {
                if !self.is_initiator() {
                    // this shouldn't be possible
                    self.state = State::Failed;
                    return Err(PsqError::IncorrectStateError);
                }

                let (local_ident_key, local_verif_key) = match &self.auth {
                    Auth::Initiator(ik, vk) => (ik, vk),
                    Auth::Responder(_) => {
                        // This should be impossible to reach
                        return Err(PsqError::IncorrectStateError);
                    }
                };

                let remote_public_key = match &self.psq {
                    Psq::Initiator(remote_public_key) => remote_public_key,
                    Psq::Responder(_, _) => {
                        // This should be impossible to reach
                        return Err(PsqError::IncorrectStateError);
                    }
                };

                // Generate the first PSQ message
                let (state, msg) = Initiator::send_initial_message::<C, T>(
                    self.ctx.as_bytes(),
                    self.psk_ttl.unwrap_or(DEFAULT_PSK_TTL),
                    remote_public_key,
                    local_ident_key,
                    local_verif_key,
                    rng,
                )?;
                let encoded_msg = msg.encode();
                trace!(
                    "attepting to write {}B for initiator msg into {}B buffer",
                    encoded_msg.len(),
                    buffer.len()
                );

                buffer[..encoded_msg.len()].copy_from_slice(&encoded_msg);

                (
                    Ok(encoded_msg.len()),
                    State::InitiatorAwaitingReceive(state),
                )
            }
            State::ResponderAwaitingSend(encoded_msg, psk) => {
                if self.is_initiator() {
                    // this shouldn't be possible
                    self.state = State::Failed;
                    return Err(PsqError::IncorrectStateError);
                }

                // Send the responder message
                buffer[..encoded_msg.len()].copy_from_slice(encoded_msg);

                (
                    Ok(encoded_msg.len()),
                    State::Finished(RegisteredPsk {
                        psk: psk.psk,
                        psk_handle: psk.psk_handle.clone(),
                    }),
                )
            }
            _ => (Err(PsqError::IncorrectStateError), State::Failed),
        };
        // Update the state
        self.state = next_state;
        // Return the result

        result
    }

    pub fn wants_send(&self) -> bool {
        matches!(
            &self.state,
            State::ResponderAwaitingSend(_, _) | State::InitiatorAwaitingSend
        )
    }

    pub fn wants_recv(&self) -> bool {
        matches!(
            &self.state,
            State::ResponderAwaitingReceive | State::InitiatorAwaitingReceive(_)
        )
    }

    pub fn get_psk(&self) -> Result<RegisteredPsk, PsqError> {
        match &self.state {
            State::Finished(psk) => Ok(RegisteredPsk {
                psk: psk.psk,
                psk_handle: psk.psk_handle.clone(),
            }),
            _ => Err(PsqError::IncorrectStateError),
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(&self.state, State::Failed)
    }

    pub fn is_finished(&self) -> bool {
        matches!(&self.state, State::Finished(_))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use libcrux_kem::{Algorithm, key_gen};
    use libcrux_psq::{
        cred::Ed25519,
        impls::{MlKem768, X25519},
    };

    #[test]
    fn test_psk_mutual_auth_success() {
        crate::test::init_subscriber();

        let mut rng = rand::rng();

        info!("mlkem768");
        let (resp_dk, resp_ek) = key_gen(Algorithm::MlKem768, &mut rng).unwrap();
        test_psk_mutual_auth_success_inner::<MlKem768>(resp_dk, resp_ek);

        info!("x25519");
        let (resp_dk, resp_ek) = key_gen(Algorithm::X25519, &mut rng).unwrap();
        test_psk_mutual_auth_success_inner::<X25519>(resp_dk, resp_ek);
        // info!("Xwing");
        // let (resp_dk, resp_ek) = key_gen(Algorithm::XWingKemDraft02, &mut rng).unwrap();
        // test_psk_mutual_auth_success_inner::<XWingKemDraft02>(resp_dk, resp_ek);
    }

    fn test_psk_mutual_auth_success_inner<T>(
        resp_dk: <T::InnerKEM as KEM>::DecapsulationKey,
        resp_ek: <T::InnerKEM as KEM>::EncapsulationKey,
    ) where
        T: PSQ,
        InitiatorMsg<<T as PSQ>::InnerKEM>: Decode,
    {
        const CTX: &str = "example ctx";
        const HANDLE: &str = "example handle";

        let mut rng = rand::rng();
        let (init_signing_key, init_verif_key) =
            libcrux_ed25519::generate_key_pair(&mut rng).unwrap();
        let init_signing_key = init_signing_key.into_bytes();
        let init_verif_key = init_verif_key.into_bytes();
        let init_cert = init_verif_key.clone();

        // info shared ahead of time out of band
        //    responder -> initiator: resp_pubkey, CTX
        //    initiator -> responder: init_verif_key

        let mut initiator: PsqProtocol<Ed25519, T> = PsqBuilder::new()
            .with_psk_ttl(Duration::from_secs(10))
            .remote_public_key(&resp_ek)
            .initiator_auth(&init_signing_key, &init_verif_key)
            .with_ctx(CTX)
            .build_initiator()
            .expect("failed to build initiator");

        let mut responder: PsqProtocol<Ed25519, T> = PsqBuilder::new()
            .local_key_pair(&resp_dk, &resp_ek)
            .with_psk_ttl(Duration::from_secs(10))
            .initiator_cert(&init_cert)
            .with_handle(HANDLE)
            .with_ctx(CTX)
            .build_responder()
            .expect("failed to build responder");

        assert!(initiator.is_initiator());
        assert!(!responder.is_initiator());

        let mut network = [0u8; 16384];

        while !initiator.is_finished() || !responder.is_finished() {
            if initiator.wants_send() {
                let msg = &mut network[..];
                let n = initiator
                    .get_bytes_to_send(&mut rng, msg)
                    .expect("failed to construct initiator message");

                debug!("I -> R ({}B): {:?}", n, hex::encode(&msg[..n]));

                responder
                    .read_message(&msg[..n])
                    .expect("responder failed to read message from initiator");
            }

            if responder.wants_send() {
                let msg = &mut network[..];

                let n = responder
                    .get_bytes_to_send(&mut rng, msg)
                    .expect("failed construct responder message");

                debug!("R -> I ({}B): {:?}", n, hex::encode(&msg[..n]));

                initiator
                    .read_message(&msg[..n])
                    .expect("initiator failed to read message from responder");
            }
        }

        let initiator_psk = initiator
            .get_psk()
            .expect("initiator failed to construct the PSK");
        let responder_psk = responder
            .get_psk()
            .expect("responder failed to construct the PSK");
        assert_eq!(initiator_psk.psk, responder_psk.psk);
        assert_eq!(initiator_psk.psk_handle, responder_psk.psk_handle);

        debug!("PSK: {:?}", hex::encode(initiator_psk.psk));
    }
}
