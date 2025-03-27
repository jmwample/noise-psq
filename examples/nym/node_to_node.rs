//! Example demonstrating and workshoping the interface for establishing mutually
//! authenticated connections between nodes that know about eachother ahead of time.

use std::io;

use nymnoise::{
    NoiseError,
    stream::{NoisePattern, NoiseStream},
    upgrade_noise_initiator, upgrade_noise_responder,
};
use pin_project::pin_project;
use snow::{Error as SnowError, error::Prerequisite};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tracing::*;

struct Node {
    ident_key: (),
    static_key: (),
    node_id: u64,
}

struct NodeDescriptor {
    ident_cert: (),
    public_key: (),
    node_id: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

pub async fn upgrade_noise_responder_with_topology(
    conn: TcpStream,
    pattern: NoisePattern,
    topology: &NymTopology,
    epoch: u32,
    local_public_key: &encryption::PublicKey,
    local_private_key: &encryption::PrivateKey,
) -> Result<NoiseStream<TcpStream>, NoiseError> {
    //Get init material
    let initiator_addr = match conn.peer_addr() {
        Ok(addr) => addr,
        Err(err) => {
            error!("Unable to extract peer address from connection - {err}");
            return Err(SnowError::Prereq(Prerequisite::RemotePublicKey).into());
        }
    };

    match topology.find_node_key_by_mix_host(initiator_addr, false) {
        Ok(Some(_)) => {
            //Existing node supporting Noise
            upgrade_noise_responder(conn, pattern, local_public_key, local_private_key, epoch).await
        }
        Ok(None) => {
            //Existing node not supporting Noise yet
            warn!(
                "{:?} can't speak Noise yet, falling back to TCP",
                initiator_addr
            );
            Ok(conn)
        }
        Err(_) => {
            //Non existing node
            error!(
                "Cannot find public key for node with address {:?}",
                initiator_addr
            ); //Do we still pursue a TCP connection with that node or not?
            Err(SnowError::Prereq(Prerequisite::RemotePublicKey).into())
        }
    }
}

pub async fn upgrade_noise_initiator_with_topology(
    conn: TcpStream,
    pattern: NoisePattern,
    topology: &NymTopology,
    epoch: u32,
    local_private_key: &encryption::PrivateKey,
) -> Result<NoiseStream<TcpStream>, NoiseError> {
    //Get init material
    let responder_addr = conn.peer_addr().map_err(|err| {
        error!("Unable to extract peer address from connection - {err}");
        SnowError::Prereq(Prerequisite::RemotePublicKey)
    })?;

    let remote_pub_key = match topology.find_node_key_by_mix_host(responder_addr, true) {
        Ok(Some(key)) => encryption::PublicKey::from_base58_string(key)?,
        Ok(None) => {
            warn!(
                "{:?} can't speak Noise yet, falling back to TCP",
                responder_addr
            );
            return Ok(conn);
        }
        Err(_) => {
            error!(
                "Cannot find public key for node with address {:?}",
                responder_addr
            ); //Do we still pursue a TCP connection or not?
            return Err(SnowError::Prereq(Prerequisite::RemotePublicKey).into());
        }
    };

    upgrade_noise_initiator(conn, pattern, local_private_key, &remote_pub_key, epoch).await
}

#[pin_project(project = ConnectionProj)]
pub enum Connection {
    Tcp(#[pin] TcpStream),
    Noise(#[pin] NoiseStream<TcpStream>),
}

impl Connection {
    pub fn peer_addr(&self) -> Result<std::net::SocketAddr, io::Error> {
        match self {
            Self::Noise(stream) => stream.get_ref().peer_addr(),
            Self::Tcp(stream) => stream.peer_addr(),
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            ConnectionProj::Noise(stream) => stream.poll_read(cx, buf),
            ConnectionProj::Tcp(stream) => stream.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match self.project() {
            ConnectionProj::Noise(stream) => stream.poll_write(cx, buf),
            ConnectionProj::Tcp(stream) => stream.poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.project() {
            ConnectionProj::Noise(stream) => stream.poll_flush(cx),
            ConnectionProj::Tcp(stream) => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.project() {
            ConnectionProj::Noise(stream) => stream.poll_shutdown(cx),
            ConnectionProj::Tcp(stream) => stream.poll_shutdown(cx),
        }
    }
}
