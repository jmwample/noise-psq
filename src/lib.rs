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
pub mod stream;

use crate::error::NoiseError;
use crate::stream::{NoisePattern, NoiseStream};
use sha2::{Digest, Sha256};
use snow::Builder;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::*;

const NOISE_PSK_PREFIX: &[u8] = b"NYMTECH_NOISE_dQw4w9WgXcQ";

/// Given an async read/write stream initiate a noise handshake using the specified
/// pattern and provided keys. On success a wrapped connection is returned.
pub async fn upgrade_noise_initiator<C>(
    conn: C,
    pattern: NoisePattern,
    local_private_key: impl AsRef<[u8]>,
    remote_pub_key: impl AsRef<[u8]>,
    epoch: u32,
) -> Result<NoiseStream<C>, NoiseError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    debug!("Perform Noise Handshake, initiator side");

    let secret = [
        NOISE_PSK_PREFIX.to_vec(),
        remote_pub_key.as_ref().to_vec(),
        epoch.to_be_bytes().to_vec(),
    ]
    .concat();
    let secret_hash = Sha256::digest(secret);

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
    conn: C,
    pattern: NoisePattern,
    local_public_key: impl AsRef<[u8]>,
    local_private_key: impl AsRef<[u8]>,
    epoch: u32,
) -> Result<NoiseStream<C>, NoiseError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    debug!("Perform Noise Handshake, responder side");

    let secret = [
        NOISE_PSK_PREFIX.to_vec(),
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

    use rand::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x25519_dalek::{PublicKey, StaticSecret};

    const BUF_SIZE: usize = 16384;

    #[tokio::test]
    async fn handshake_plain() {
        init_subscriber();
        trace!("beginning");

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
        // let ini_public_key = PublicKey::from(&resp_secret).to_bytes();
        trace!("setup complete");

        tokio::spawn(async move {
            trace!("starting responder");
            let mut conn = match upgrade_noise_responder(
                res,
                NoisePattern::XKpsk3,
                &resp_public_key[..],
                &resp_private_key[..],
                epoch.clone(),
            )
            .await
            {
                Err(e) => {
                    error!("responder failed noise handshake: {e}");
                    return ();
                }
                Ok(c) => c,
            };

            trace!("responder established, attempting to read");

            let mut buf = [0u8; TEST_MSG.len()];
            conn.read_exact(&mut buf[..])
                .await.expect("read faild");
            trace!("responder read complete");

            // let the initiator prepare to read before we write
            tokio::time::sleep(Duration::from_millis(500)).await;

            trace!("responder attempting to write");
            assert_eq!(buf, TEST_MSG);
            buf.reverse();
            conn.write_all(&buf[..]).await.expect("write failed");

            trace!("responder success");
        });

        // let the responder set up
        tokio::time::sleep(Duration::from_millis(500)).await;
        trace!("beginning initiator hs");

        let mut conn = match upgrade_noise_initiator(
            ini,
            NoisePattern::XKpsk3,
            ini_private_key,
            resp_public_key,
            epoch,
        )
        .await
        {
            Err(e) => {
                error!("responder failed noise handshake: {e}");
                return ();
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
    }

    use std::{env, str::FromStr, sync::Once};

    use tracing_subscriber::filter::LevelFilter;

    #[tokio::test]
    async fn handshake_failure() {}

    static SUBSCRIBER_INIT: Once = Once::new();

    pub fn init_subscriber() {
        SUBSCRIBER_INIT.call_once(|| {
            let level = env::var("RUST_LOG").unwrap_or("trace".into());
            let lf = LevelFilter::from_str(&level).unwrap();

            tracing_subscriber::fmt().with_max_level(lf).init();
        });
    }
}
