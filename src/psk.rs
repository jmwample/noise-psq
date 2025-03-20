//! Implementations for optional Pre-Shared Key establishment

use crate::error::NoiseError;

use std::time::Duration;

use libcrux_psq::{cred::Authenticator, traits::PSQ};
use rand::CryptoRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

pub trait PSK {
    type Psk: AsRef<[u8]>;
    type Initiator: PskInitiator<Psk = Self::Psk>;
    type Responder: PskResponder<Psk = Self::Psk>;
}

pub trait PskInitiator {
    type Psk: AsRef<[u8]>;
    type Error: std::fmt::Debug;

    async fn initiator_establish_psk<S>(
        &self,
        conn: &mut S,
        rng: &mut impl CryptoRng,
        ctx: impl AsRef<[u8]>,
    ) -> Result<Self::Psk, Self::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin;
}

pub trait PskResponder {
    type Psk: AsRef<[u8]>;
    type Error: std::fmt::Debug;

    async fn responder_establish_psk<S>(
        &self,
        conn: &mut S,
        ctx: impl AsRef<[u8]>,
    ) -> Result<Self::Psk, Self::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin;
}

pub struct NoPsk {}

impl PSK for NoPsk {
    type Psk = [u8;0];
    type Initiator = Self;
    type Responder = Self;
}

impl PskInitiator for NoPsk {
    type Psk = [u8;0];
    type Error = ();

    async fn initiator_establish_psk<S>(
        &self,
        _conn: &mut S,
        _rng: &mut impl CryptoRng,
        _ctx: impl AsRef<[u8]>,
    ) -> Result<Self::Psk, Self::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Ok([0u8;0])
    }
}

impl PskResponder for NoPsk {
    type Psk = [u8;0];
    type Error = ();

    async fn responder_establish_psk<S>(
        &self,
        _conn: &mut S,
        _ctx: impl AsRef<[u8]>,
    ) -> Result<Self::Psk, Self::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin
    {
        Ok([0u8;0])
    }
}

pub mod psq {
    use std::marker::PhantomData;

    use super::*;

    use libcrux_psq::{
        psk_registration::{Initiator, InitiatorMsg, Responder, ResponderMsg},
        traits::{Decode, Encode},
    };
    use libcrux_traits::kem::KEM;

    const DEFAULT_PSK_TTL: Duration = Duration::from_secs(3600);
    const PSK_LENGTH: usize = 32;
    type PsqPsk = [u8; PSK_LENGTH];

    pub struct Psq<C, T>
    where
        C: Authenticator,
        T: PSQ,
        InitiatorMsg<<T as PSQ>::InnerKEM>: Decode,
    {
        psq: PhantomData<T>,
        auth: PhantomData<C>,
    }

    impl<C, T> PSK for Psq<C, T>
    where
        C: Authenticator,
        T: PSQ,
        InitiatorMsg<<T as PSQ>::InnerKEM>: Decode,
    {
        type Psk = PsqPsk;
        type Initiator = PsqInitiator<C, T>;
        type Responder = PsqResponder<C, T>;
    }

    pub struct PsqInitiator<C: Authenticator, T: PSQ> {
        pub auth_ident_key: C::SigningKey,
        pub auth_ident_cred: C::Credential,
        pub psq_ek: <T::InnerKEM as KEM>::EncapsulationKey,
        pub psk_ttl: Option<Duration>,
    }

    impl<C: Authenticator, T: PSQ> PskInitiator for PsqInitiator<C, T>
    where
        C: Authenticator,
        T: PSQ,
        InitiatorMsg<<T as PSQ>::InnerKEM>: Encode,
    {
        type Psk = PsqPsk;
        type Error = NoiseError;

        async fn initiator_establish_psk<S>(
            &self,
            conn: &mut S,
            rng: &mut impl CryptoRng,
            ctx: impl AsRef<[u8]>,
        ) -> Result<Self::Psk, Self::Error>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            // Generate the first PSQ message
            let (state, msg) = Initiator::send_initial_message::<C, T>(
                ctx.as_ref(),
                self.psk_ttl.unwrap_or(DEFAULT_PSK_TTL),
                &self.psq_ek,
                &self.auth_ident_key,
                &self.auth_ident_cred,
                rng,
            )
            .unwrap();
            let encoded_msg = msg.encode();
            trace!("sending {} bytes for initiator msg", encoded_msg.len());
            conn.write_all(&(encoded_msg.len() as u64).to_be_bytes())
                .await?;
            conn.write_all(&encoded_msg).await?;

            // Read the response
            let mut msg_size = [0u8; 8];
            conn.read_exact(&mut msg_size).await?;
            let msg_size = u64::from_be_bytes(msg_size);
            trace!("reading {} bytes for responder msg", msg_size);

            let mut responder_msg = vec![0u8; msg_size as usize];
            conn.read_exact(&mut responder_msg).await?;
            let (responder_msg, _) = ResponderMsg::decode(&responder_msg)?;

            // Finish the handshake
            let psk = state.complete_handshake(&responder_msg)?;

            debug!(
                "Registered psk for: {}",
                String::from_utf8(psk.psk_handle.clone()).unwrap()
            );
            debug!("  with psk: {:x?}", psk.psk);

            Ok(psk.psk)
        }
    }

    pub struct PsqResponder<C: Authenticator, T: PSQ> {
        pub auth_ident_cert: C::Certificate,
        pub psq_ek: <T::InnerKEM as KEM>::EncapsulationKey,
        pub psq_dk: <T::InnerKEM as KEM>::DecapsulationKey,
        pub psk_ttl: Option<Duration>,
        pub handle: String, // todo: change type?
    }

    impl<C, T> PskResponder for PsqResponder<C, T>
    where
        C: Authenticator,
        T: PSQ,
        InitiatorMsg<<T as PSQ>::InnerKEM>: Decode,
    {
        type Psk = PsqPsk;
        type Error = NoiseError;

        async fn responder_establish_psk<S>(
            &self,
            conn: &mut S,
            ctx: impl AsRef<[u8]>,
        ) -> Result<Self::Psk, Self::Error>
        where
            S: AsyncRead + AsyncWrite + Unpin,
        {
            // Read the initial PSQ message.
            // First the length as u64.
            let mut msg_size = [0u8; 8];
            conn.read_exact(&mut msg_size).await?;
            let msg_size = u64::from_be_bytes(msg_size);
            trace!("reading {} bytes for initiator msg", msg_size);

            let mut msg = vec![0u8; msg_size as usize];
            conn.read_exact(&mut msg).await?;
            let (msg, _) = InitiatorMsg::<T::InnerKEM>::decode(&msg)?;

            let (psk, msg) = Responder::send::<C, T>(
                self.handle.as_bytes(),
                self.psk_ttl.unwrap_or(DEFAULT_PSK_TTL),
                ctx.as_ref(),
                &self.psq_ek,
                &self.psq_dk,
                &self.auth_ident_cert,
                &msg,
            )?;

            trace!("received valid initiator msg");

            // Send the message back.
            let encoded_msg = msg.encode();
            let msg_size = (encoded_msg.len() as u64).to_be_bytes();
            conn.write_all(&msg_size).await?;
            conn.write_all(&encoded_msg).await?;

            debug!(
                "Registered psk for: {}",
                String::from_utf8(psk.psk_handle.clone()).unwrap()
            );
            debug!("  with psk: {:x?}", psk.psk);

            Ok(psk.psk)
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_psk_generic() {

        todo!();

    }

}
