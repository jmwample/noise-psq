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

    async fn initiator_establish_psk<S>(
        &self,
        conn: &mut S,
        rng: &mut impl CryptoRng,
        ctx: impl AsRef<[u8]>,
    ) -> Result<Self::Psk, NoiseError>
    where
        S: AsyncRead + AsyncWrite + Unpin;
}

pub trait PskResponder {
    type Psk: AsRef<[u8]>;

    async fn responder_establish_psk<S>(
        &self,
        conn: &mut S,
        ctx: impl AsRef<[u8]>,
    ) -> Result<Self::Psk, NoiseError>
    where
        S: AsyncRead + AsyncWrite + Unpin;
}

pub struct NoPsk {}

impl PSK for NoPsk {
    type Psk = [u8; 0];
    type Initiator = Self;
    type Responder = Self;
}

impl PskInitiator for NoPsk {
    type Psk = [u8; 0];

    async fn initiator_establish_psk<S>(
        &self,
        _conn: &mut S,
        _rng: &mut impl CryptoRng,
        _ctx: impl AsRef<[u8]>,
    ) -> Result<Self::Psk, NoiseError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Ok([0u8; 0])
    }
}

impl PskResponder for NoPsk {
    type Psk = [u8; 0];

    async fn responder_establish_psk<S>(
        &self,
        _conn: &mut S,
        _ctx: impl AsRef<[u8]>,
    ) -> Result<Self::Psk, NoiseError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Ok([0u8; 0])
    }
}

pub mod psq;
