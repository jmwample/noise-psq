use std::{env, str::FromStr};

use clap::Parser;
use libcrux_psq::{
    cred::{Authenticator, Ed25519},
    impls::{MlKem768, X25519},
};
use libcrux_traits::kem::KEM;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::*;
use tracing_subscriber::filter::LevelFilter;

use nymnoise::{
    NoiseError,
    psk::{PSK, PskInitiator, PskResponder},
};

mod nym;
use nym::{Node, NodeDescriptor};

/// This is hardcoded for ML-KEM 768, for ClassicMcEliece it would be `524160`.
const RESPONDER_PK_LEN: usize = 1184;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Side {
    NodeInit,
    ClientInit,
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

#[tokio::main]
async fn main() {
    let level = env::var("RUST_LOG").unwrap_or("trace".into());
    let lf = LevelFilter::from_str(&level).unwrap();
    tracing_subscriber::fmt().with_max_level(lf).init();

    let args = Args::parse();

    if args.handle.is_some() && matches!(args.side, Side::NodeInit | Side::ClientInit) {
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
        Side::ClientInit => client_initiator(host, port, ctx).await.unwrap(),
        Side::NodeInit => node_initiator(host, port, ctx).await.unwrap(),
        Side::Responder => node_responder(host, port, ctx, handle).await.unwrap(),
    };
}

async fn client_initiator(host: String, port: u16, ctx: String) -> Result<(), NoiseError> {
    todo!()
}

/// The initiator protocol
async fn node_initiator(host: String, port: u16, ctx: String) -> Result<(), NoiseError> {
    // Set up networking
    let mut stream = TcpStream::connect((host.clone(), port)).await?;
    stream.set_nodelay(true)?;

    info!("Starting new Initiator connection ...");
    debug!("  {host}:{port}");


    let node = Node::<X25519>::default().with_sctx(ctx);
    let descriptor = NodeDescriptor::from(&node);

    // This setup is outside of PSQ but required to set up both sides for the protocol.
    let (sk, credential, responder_pk) = {
        // Register an Ed25519 identity with the responder.
        let mut rng = rand::rng();
        let (sk, pk) = libcrux_ed25519::generate_key_pair(&mut rng).unwrap();

        // Send the public key to the responder
        stream.write_all(pk.as_ref()).await?;

        // Get the responder's public key.
        let mut responder_pk = [0u8; RESPONDER_PK_LEN];
        stream.read_exact(&mut responder_pk).await?;
        let responder_pk = <libcrux_psq::impls::MlKem768 as KEM>::EncapsulationKey::decode(
            libcrux_kem::Algorithm::MlKem768,
            &responder_pk,
        )?;

        (sk, pk, responder_pk)
    };

    let psk = nymnoise::psk::psq::PsqInitiator::<Ed25519, MlKem768> {
        auth_ident_key: sk.into_bytes(),
        auth_ident_cred: credential.into_bytes(),
        psq_ek: responder_pk,
        psk_ttl: None,
    };

    let mut rng = rand::rng();
    let psk = psk
        .initiator_establish_psk(&mut stream, &mut rng, ctx)
        .await?;

    debug!("  with psk: {:x?}", hex::encode(psk));

    Ok(())
}

async fn node_responder(host: String, port: u16, ctx: String, handle: String) -> Result<(), NoiseError> {
    let listener = TcpListener::bind((host.as_str(), port)).await?;

    info!("Listening for incoming connection ...");
    debug!("  {host}:{port}");
    
    let node = Node::<X25519>::default().with_handle(handle).with_sctx(ctx);
    let descriptor = NodeDescriptor::from(&node);

    loop {
        let (mut stream, _) = listener.accept().await?;

        info!("  Accepted incoming connection ...");

        // Setup before running PSQ
        let (initiator_credential, sk, pk) = {
            // Read and store the initiator identity.
            let mut initiator_credential = [0u8; Ed25519::CRED_LEN];
            stream.read_exact(&mut initiator_credential).await?;

            // Generate the responder key pair.
            let mut rng = rand::rng();
            let (sk, pk) = MlKem768::generate_key_pair(&mut rng).unwrap();

            // Send the public key to the initiator.
            stream.write_all(&pk.encode()).await?;

            (initiator_credential, sk, pk)
        };

        let psk = node.establish_psk(&mut stream, &other);
       

        info!("negotiated psk: {:x?}", hex::encode(psk));
    }
}
