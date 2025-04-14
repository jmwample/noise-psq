// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

//! Nym Noise Protocol
//!
//! This is a network transport for wrapping generic async read/write in a secure
//! encrypted tunnel.
//!
//! The tunnel is based on the noise protocol using IKpsk2 or XKpsk3 based on a
//! a secret established using a cusom psq handshake.
//#![deny(missing_docs)]
#![warn(missing_docs)]

pub mod error;
pub mod psk;
pub mod stream;

pub use crate::error::NoiseError;
use crate::psk::{PskInitiator, PskResponder};
use crate::stream::{NoisePattern, NoiseStream};

use rand::prelude::*;
use sha2::{Digest, Sha256};
use snow::Builder;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::*;

use std::time::Duration;

const NOISE_PSK_PREFIX: &[u8] = b"NYMTECH_NOISE_dQw4w9WgXcQ";

/// Given an async read/write stream initiate a noise handshake using the specified
/// pattern and provided keys. On success a wrapped connection is returned.
pub async fn upgrade_noise_initiator<C, P>(
    mut conn: C,
    rng: &mut impl CryptoRng,
    pattern: NoisePattern,
    local_private_key: impl AsRef<[u8]>,
    remote_pub_key: impl AsRef<[u8]>,
    psk_initiator: P::Initiator,
    epoch: u32,
    ctx: String,
) -> Result<NoiseStream<C>, NoiseError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: psk::PSK,
{
    debug!("Perform Noise Handshake, initiator side");

    let psk = psk_initiator
        .initiator_establish_psk(&mut conn, rng, ctx)
        .await?;

    let secret = [
        NOISE_PSK_PREFIX.to_vec(),
        psk.as_ref().to_vec(),
        remote_pub_key.as_ref().to_vec(),
        epoch.to_be_bytes().to_vec(),
    ]
    .concat();
    let secret_hash = Sha256::digest(secret);

    // perform the Noise handshake with the negotiated PQPSK
    let handshake = Builder::new(pattern.as_str().parse()?)
        .local_private_key(local_private_key.as_ref())
        .remote_public_key(remote_pub_key.as_ref())
        .psk(pattern.psk_position(), &secret_hash)
        .build_initiator()?;

    let noise_stream = NoiseStream::new(conn, handshake);

    Ok(noise_stream.perform_handshake().await?)
}

/// Given an async read/write stream attempt to listen for and respond to a noise
/// handshake using the specified pattern and provided keys. On success a wrapped
/// connection is returned.
pub async fn upgrade_noise_responder<C, P>(
    mut conn: C,
    pattern: NoisePattern,
    local_public_key: impl AsRef<[u8]>,
    local_private_key: impl AsRef<[u8]>,
    psk_responder: P::Responder,
    epoch: u32,
    ctx: String,
) -> Result<NoiseStream<C>, NoiseError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: psk::PSK,
{
    debug!("Perform Noise Handshake, responder side");

    let psk = psk_responder
        .responder_establish_psk(&mut conn, ctx)
        .await?;

    let secret = [
        NOISE_PSK_PREFIX.to_vec(),
        psk.as_ref().to_vec(),
        local_public_key.as_ref().to_vec(),
        epoch.to_be_bytes().to_vec(),
    ]
    .concat();
    let secret_hash = Sha256::digest(secret);

    let handshake = Builder::new(pattern.as_str().parse()?)
        .local_private_key(local_private_key.as_ref())
        .psk(pattern.psk_position(), &secret_hash)
        .build_responder()?;

    let noise_stream = NoiseStream::new(conn, handshake);

    Ok(noise_stream.perform_handshake().await?)
}

#[cfg(test)]
mod test {
    use super::*;

    use std::time::Duration;
    use std::{env, str::FromStr, sync::Once};

    use libcrux_psq::cred::Ed25519;
    use libcrux_psq::impls::X25519;
    use libcrux_traits::kem::KEM;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing_subscriber::filter::LevelFilter;
    use x25519_dalek::{PublicKey, StaticSecret};

    static SUBSCRIBER_INIT: Once = Once::new();

    const BUF_SIZE: usize = 16384;

    pub fn init_subscriber() {
        SUBSCRIBER_INIT.call_once(|| {
            let level = env::var("RUST_LOG").unwrap_or("trace".into());
            let lf = LevelFilter::from_str(&level).unwrap();

            tracing_subscriber::fmt().with_max_level(lf).init();
        });
    }

    #[tokio::test]
    async fn handshake_plain() {
        init_subscriber();
        trace!("beginning");

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        let ctx = "example application context".to_string();
        let resp_ctx = ctx.clone();
        let handle = "psq example handle".to_string();
        const TEST_MSG: &[u8] = b"helloooooooooooooooooooooooooooooooooooooooooooooooooooooo";
        const TEST_MSG_REV: &[u8] = b"oooooooooooooooooooooooooooooooooooooooooooooooooooooolleh";
        let (ini, res) = tokio::io::duplex(BUF_SIZE);

        let mut rng = rand::rng();
        let epoch = rng.next_u32();

        let resp_secret = StaticSecret::random();
        let resp_private_key = resp_secret.to_bytes();
        let resp_public_key = PublicKey::from(&resp_secret).to_bytes();

        let ini_secret = StaticSecret::random();
        let ini_private_key = ini_secret.to_bytes();
        let (ini_ident_privkey, ini_ident_cred) =
            libcrux_ed25519::generate_key_pair(&mut rng).unwrap();
        let ini_cred_bytes = ini_ident_cred.into_bytes();

        trace!("setup complete");

        tokio::spawn(async move {
            trace!("starting responder");

            let psk_responder = psk::psq::PsqResponder::<Ed25519, X25519> {
                auth_ident_cert: ini_cred_bytes,
                psq_ek: libcrux_kem::PublicKey::decode(
                    libcrux_kem::Algorithm::X25519,
                    &resp_public_key[..],
                )
                .unwrap(),
                psq_dk: libcrux_kem::PrivateKey::decode(
                    libcrux_kem::Algorithm::X25519,
                    &resp_private_key[..],
                )
                .unwrap(),
                psk_ttl: None,
                handle,
            };

            let mut conn = match upgrade_noise_responder::<
                tokio::io::DuplexStream,
                psk::psq::Psq<Ed25519, X25519>,
            >(
                res,
                NoisePattern::XKpsk3,
                &resp_public_key[..],
                &resp_private_key[..],
                psk_responder,
                epoch.clone(),
                resp_ctx,
            )
            .await
            {
                Err(e) => {
                    error!("responder failed noise handshake: {e}");
                    tx.send(format!("responder failed noise handshake: {e}"))
                        .expect("test somehow dropped the error sync channelreceiver");
                    return ();
                }
                Ok(c) => c,
            };

            trace!("responder established, attempting to read");

            let mut buf = [0u8; TEST_MSG.len()];
            conn.read_exact(&mut buf[..]).await.expect("read faild");
            trace!("responder read complete");

            // let the initiator prepare to read before we write
            tokio::time::sleep(Duration::from_millis(500)).await;

            trace!("responder attempting to write");
            assert_eq!(buf, TEST_MSG);
            buf.reverse();
            conn.write_all(&buf[..]).await.expect("write failed");

            trace!("responder success");
            tx.send(String::new())
                .expect("test somehow dropped the error sync channelreceiver");
        });

        // let the responder set up
        tokio::time::sleep(Duration::from_millis(500)).await;
        trace!("beginning initiator hs");

        let psk_initiator = psk::psq::PsqInitiator::<Ed25519, X25519> {
            psq_ek: libcrux_kem::PublicKey::decode(
                libcrux_kem::Algorithm::X25519,
                &resp_public_key[..],
            )
            .unwrap(),
            auth_ident_key: ini_ident_privkey.into_bytes(),
            auth_ident_cred: ini_cred_bytes,
            psk_ttl: None,
        };

        let mut conn = match upgrade_noise_initiator::<
            tokio::io::DuplexStream,
            psk::psq::Psq<Ed25519, X25519>,
        >(
            ini,
            &mut rng,
            NoisePattern::XKpsk3,
            ini_private_key,
            resp_public_key,
            psk_initiator,
            epoch,
            ctx,
        )
        .await
        {
            Err(e) => {
                panic!("initiator failed noise handshake: {e}");
            }
            Ok(c) => c,
        };

        trace!("initiator established");

        // let the responder prepare to read before we write
        tokio::time::sleep(Duration::from_millis(500)).await;

        trace!("initiator attempting to write");

        conn.write_all(TEST_MSG).await.expect("write failed");

        trace!("initiator write complete, attempting to read");

        let mut buf = [0u8; TEST_MSG.len()];
        conn.read_exact(&mut buf[..]).await.expect("read faild");
        assert_eq!(TEST_MSG_REV, buf);

        trace!("initiator success");
        match rx.await {
            Err(e) => panic!("failed to get responder success {e}"),
            Ok(s) => assert!(s.is_empty()),
        };
    }

    // #[tokio::test]
    // async fn handshake_failure() {}
}
