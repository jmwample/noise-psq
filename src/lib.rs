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
pub use error::NoiseError;
pub mod stream;
pub mod psk;

use crate::stream::{NoisePattern, NoiseStream};
use libcrux_kem::{PrivateKey, PublicKey};
use libcrux_psq::{
    cred::Ed25519,
    impls::X25519,
    psk_registration::{Initiator, InitiatorMsg, Responder, ResponderMsg},
    traits::{Decode, Encode},
};
use rand::prelude::*;
use sha2::{Digest, Sha256};
use snow::Builder;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::*;

use std::time::Duration;

const NOISE_PSK_PREFIX: &[u8] = b"NYMTECH_NOISE_dQw4w9WgXcQ";
const DEFAULT_PSK_TTL: Duration = Duration::from_secs(3600);

/// Given an async read/write stream initiate a noise handshake using the specified
/// pattern and provided keys. On success a wrapped connection is returned.
pub async fn upgrade_noise_initiator<C>(
    mut conn: C,
    rng: &mut impl CryptoRng,
    pattern: NoisePattern,
    local_private_key: impl AsRef<[u8]>,
    local_ident_privkey: impl AsRef<[u8]>,
    local_ident_credential: impl AsRef<[u8]>,
    remote_pub_key: impl AsRef<[u8]>,
    epoch: u32,
    ctx: String,
) -> Result<NoiseStream<C>, NoiseError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    debug!("Perform Noise Handshake, initiator side");

    let mut local_privkey = [0u8; 32];
    local_privkey[..].copy_from_slice(&local_private_key.as_ref());
    let mut local_ident_key = [0u8; 32];
    local_ident_key[..].copy_from_slice(&local_ident_privkey.as_ref());
    let mut local_ident_cred = [0u8; 32];
    local_ident_cred[..].copy_from_slice(&local_ident_credential.as_ref());
    let remote_pubkey = PublicKey::decode(libcrux_kem::Algorithm::X25519, remote_pub_key.as_ref())?;

    // Generate the first PSQ message
    let (state, msg) = Initiator::send_initial_message::<Ed25519, X25519>(
        ctx.as_bytes(),
        DEFAULT_PSK_TTL,
        &remote_pubkey,
        &local_ident_key,
        &local_ident_cred,
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

    let secret = [
        NOISE_PSK_PREFIX.to_vec(),
        psk.psk.to_vec(),
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
pub async fn upgrade_noise_responder<C>(
    mut conn: C,
    pattern: NoisePattern,
    local_public_key: impl AsRef<[u8]>,
    local_private_key: impl AsRef<[u8]>,
    initiator_cred: impl AsRef<[u8]>,
    epoch: u32,
    ctx: String,
    handle: String,
) -> Result<NoiseStream<C>, NoiseError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    debug!("Perform Noise Handshake, responder side");

    // Read the initial PSQ message.
    // First the length as u64.
    let mut msg_size = [0u8; 8];
    conn.read_exact(&mut msg_size).await?;
    let msg_size = u64::from_be_bytes(msg_size);
    trace!("reading {} bytes for initiator msg", msg_size);

    let mut msg = vec![0u8; msg_size as usize];
    conn.read_exact(&mut msg).await?;
    let (msg, _) = InitiatorMsg::<X25519>::decode(&msg)?;

    let local_privkey =
        PrivateKey::decode(libcrux_kem::Algorithm::X25519, local_private_key.as_ref())?;
    let local_pubkey =
        PublicKey::decode(libcrux_kem::Algorithm::X25519, local_public_key.as_ref())?;
    let mut initiator_credential = [0u8; 32];
    initiator_credential[..].copy_from_slice(initiator_cred.as_ref());

    let (psk, msg) = Responder::send::<Ed25519, X25519>(
        handle.as_bytes(),
        DEFAULT_PSK_TTL,
        ctx.as_bytes(),
        &local_pubkey,
        &local_privkey,
        &initiator_credential,
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

    let secret = [
        NOISE_PSK_PREFIX.to_vec(),
        psk.psk.to_vec(),
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

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x25519_dalek::{PublicKey, StaticSecret};
    use tracing_subscriber::filter::LevelFilter;

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
        let (ini_ident_privkey, ini_ident_cred) = libcrux_ed25519::generate_key_pair(&mut rng).unwrap();
        let ini_cred_bytes = ini_ident_cred.into_bytes();

        trace!("setup complete");

        tokio::spawn(async move {
            trace!("starting responder");
            let mut conn = match upgrade_noise_responder(
                res,
                NoisePattern::XKpsk3,
                &resp_public_key[..],
                &resp_private_key[..],
                &ini_cred_bytes,
                epoch.clone(),
                resp_ctx,
                handle,
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

        let mut conn = match upgrade_noise_initiator(
            ini,
            &mut rng,
            NoisePattern::XKpsk3,
            ini_private_key,
            &ini_ident_privkey.as_ref()[..],
            &ini_cred_bytes,
            resp_public_key,
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
