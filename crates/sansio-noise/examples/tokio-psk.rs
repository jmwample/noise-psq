use sansio_noise::{
    noise::NoiseError,
    psk::{PsqError, PsqProtocol},
};

use clap::Parser;
use libcrux_psq::{
    cred::{Authenticator, Ed25519},
    impls::MlKem768,
    traits::{Decode, PSQ},
};
use libcrux_traits::kem::KEM;
use std::{env, str::FromStr};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::*;
use tracing_subscriber::filter::LevelFilter;

#[derive(Error, Debug)]
enum Error {
    #[error("Encountered an error during the PSK negotiation")]
    PsqError(#[from] PsqError),
    #[error("Encountered an IO error during the handshake")]
    IoError(#[from] std::io::Error),
    #[error("Encountered an error during the Noise handshake")]
    NoiseError(#[from] NoiseError),
    #[error("Failed to decode key material")]
    DecodeError(libcrux_kem::Error),
}

impl From<libcrux_kem::Error> for Error {
    fn from(err: libcrux_kem::Error) -> Self {
        Error::DecodeError(err)
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Side {
    Initiator,
    Responder,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Side: initiator or responder
    #[arg(value_enum)]
    side: Side,

    #[arg(long)]
    host: Option<String>,

    #[arg(long)]
    port: Option<u16>,

    #[arg(long)]
    context: Option<String>,

    #[arg(long)]
    handle: Option<String>,
}

/// This is hardcoded for ML-KEM 768, for ClassicMcEliece it would be `524160`.
const RESPONDER_PK_LEN: usize = 1184;

#[tokio::main]
pub async fn main() {
    //	// Initialize logging
    let level = env::var("RUST_LOG").unwrap_or("trace".into());
    let lf = LevelFilter::from_str(&level).unwrap();
    tracing_subscriber::fmt().with_max_level(lf).init();

    let args = Args::parse();

    if args.handle.is_some() && matches!(args.side, Side::Initiator) {
        info!("A handle can only be set on the responder.");
        return;
    }

    let host = args.host.unwrap_or("localhost".to_string());
    let port = args.port.unwrap_or(0x7071);

    let ctx = args
        .context
        .unwrap_or("example application context".to_string());
    let handle = args.handle.unwrap_or("psq example handle".to_string());

    let _ = match args.side {
        Side::Initiator => initiator(host, port, ctx).await.unwrap(),
        Side::Responder => responder(host, port, ctx, handle).await.unwrap(),
    };
}

/// The initiator protocol
async fn initiator(host: String, port: u16, ctx: String) -> Result<(), Error> {
    let mut rng = rand::rng();

    // Set up networking
    let mut stream = TcpStream::connect((host.clone(), port)).await?;
    stream.set_nodelay(true)?;

    info!("Starting new Initiator connection ...");
    debug!("  {host}:{port}");

    // This setup is outside of PSQ but required to set up both sides for the protocol.
    //
    // Send the identity cert to the responder and get the responders public encapsulation key, in
    // practice this would be pre-shared (e.g. as part of a set of node descriptors).
    let (sk, credential, responder_pk) = {
        // Register an Ed25519 identity with the responder.
        let (sk, vk) = libcrux_ed25519::generate_key_pair(&mut rng).unwrap();
        let sk = sk.into_bytes();
        let vk = vk.into_bytes();

        stream.write_all(&vk[..]).await?;

        // Get the responder's public key.
        let mut responder_pk = [0u8; RESPONDER_PK_LEN];
        stream.read_exact(&mut responder_pk).await?;
        let responder_pk = <libcrux_psq::impls::MlKem768 as KEM>::EncapsulationKey::decode(
            libcrux_kem::Algorithm::MlKem768,
            &responder_pk,
        )?;

        (sk, vk, responder_pk)
    };

    let mut psk_initiator: PsqProtocol<'_, Ed25519, MlKem768> = PsqProtocol::builder()
        .remote_public_key(&responder_pk)
        .initiator_auth(&sk, &credential)
        .with_ctx(&ctx)
        .build_initiator()?;

    psk_handshake(&mut rng, &mut stream, &mut psk_initiator).await?;
    let psk = psk_initiator.get_psk()?;

    debug!("  with psk: {:x?}", hex::encode(psk.psk));

    Ok(())
}

async fn responder(host: String, port: u16, ctx: String, handle: String) -> Result<(), Error> {
    let listener = TcpListener::bind((host.as_str(), port)).await?;

    info!("Listening for incoming connection ...");
    debug!("  {host}:{port}");

    // Generate the responder key pair.
    let mut rng = rand::rng();
    let (dk, ek) = MlKem768::generate_key_pair(&mut rng).unwrap();

    loop {
        let (mut stream, _) = listener.accept().await?;

        info!("  Accepted incoming connection ...");

        // Pre-share materials that would normally be shared out of band before running PSQ
        //
        // You could imaging this being a mutual authentication setup when we have a set of
        // descriptors with certificates for all known peers associated with IP address. So when a
        // new peer connects, we can just look up their certificate.
        let initiator_cert = {
            // Read and store the initiator identity.
            let mut initiator_cert = [0u8; Ed25519::CRED_LEN];
            stream.read_exact(&mut initiator_cert).await?;

            // Send the public key to the initiator.
            stream.write_all(&ek.encode()).await?;

            initiator_cert
        };

        let mut psk_responder: PsqProtocol<'_, Ed25519, MlKem768> = PsqProtocol::builder()
            .local_key_pair(&dk, &ek)
            .initiator_cert(&initiator_cert)
            .with_ctx(&ctx)
            .with_handle(&handle)
            .build_responder()?;

        psk_handshake(&mut rng, &mut stream, &mut psk_responder).await?;
        let psk = psk_responder.get_psk()?;

        info!("negotiated psk: {:x?}", hex::encode(psk.psk));
    }
}

async fn psk_handshake<'p, S, C, T, R>(
    rng: &mut R,
    conn: &mut S,
    psk: &mut PsqProtocol<'p, C, T>,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: Authenticator,
    T: PSQ,
    libcrux_psq::psk_registration::InitiatorMsg<<T as PSQ>::InnerKEM>: Decode,
    R: rand::CryptoRng,
{
    while !psk.is_finished() {
        if psk.wants_send() {
            let mut msg = [0u8; 16384];
            let n = psk
                .get_bytes_to_send(rng, &mut msg[..])
                .expect("failed to construct initiator message");

            let dir = if psk.is_initiator() { "I ->" } else { "R -> " };
            debug!("{dir} ({}B): {:?}", n, hex::encode(&msg[..n]));

            conn.write_all(&(n as u64).to_be_bytes()).await?;
            conn.write_all(&msg[..n]).await?;
        }
        if psk.wants_recv() {
            let mut msg = [0u8; 16384];
            let mut msg_size = [0u8; 8];
            conn.read_exact(&mut msg_size).await?;
            let msg_size = u64::from_be_bytes(msg_size) as usize;
            trace!("expecting {}B", msg_size);
            let n = conn.read_exact(&mut msg[..msg_size]).await?;

            let dir = if psk.is_initiator() { " -> I" } else { " -> R" };
            debug!("{dir} ({}B): {:?}", n, hex::encode(&msg[..n]));

            psk.read_message(&msg[..n])
                .inspect_err(|e| error!("failed read mesage: {e}"))?;
        }
    }
    Ok(())
}
