use libcrux_psq::psk_registration::{InitiatorMsg, ResponderMsg};
use libcrux_psq::traits::{Encode, Decode, PSQ};
use libcrux_psq::cred::Ed25519;
use libcrux_traits::kem::KEM;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};

use nymnoise::psk::{PskInitiator, PskResponder,  psq::PsqResponder};

type ED25519IdentKey = [u8; 32];
type ED25519IdentCert = [u8; 32];

pub struct Node<T: PSQ> {
    ident_key: ED25519IdentKey,
    static_key: <T::InnerKEM as KEM>::DecapsulationKey,
    public_key: <T::InnerKEM as KEM>::EncapsulationKey,
    node_id: u32,
    sctx: String,
    handle: String,

    descriptor: NodeDescriptor,
}

impl<T: PSQ> Default for Node<T> {
    fn default() -> Self {
        let mut rng = rand::rng();
        let (ident_key, ident_cert) = libcrux_ed25519::generate_key_pair(&mut rng).unwrap();
        let (static_key, public_key) = <T::InnerKEM as KEM>::generate_key_pair(&mut rng).unwrap();
        let node_id = rng.next_u32();

        Self {
            descriptor: NodeDescriptor {
                ident_cert: ident_cert.into_bytes(),
                public_key: public_key.encode(),
                node_id,
                sctx: String::new(),
            },

            ident_key: ident_key.into_bytes(),
            static_key,
            public_key,
            node_id,
            sctx: String::new(),
            handle: String::new(),
        }
    }
}

impl<T:PSQ> Node<T> {
    pub fn with_sctx(mut self, sctx: String) -> Self {
        self.sctx = sctx;
        self
    }

    pub fn with_handle(mut self, handle: String) -> Self {
        self.handle = handle;
        self
    }

    pub async fn responder_establish_psk<S>(stream: &mut S, other: &Self) -> <T::InnerKEM as KEM>::SharedSecret
    where
        S: AsyncWrite + AsyncRead + Unpin,
        InitiatorMsg<T::InnerKEM>: Decode,
    {
        let r = PsqResponder::<Ed25519, T> {
            auth_ident_cert: other.ident_cert,
            psq_ek: &self.public_key,
            psq_dk: &self.static_key,
            psk_ttl: None,
            handle: self.handle.clone(),
        };

        r.responder_establish_psk(stream, other.sctx.clone()).await.unwrap()
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeDescriptor {
    ident_cert: ED25519IdentCert,
    public_key: Vec<u8>,
    node_id: u32,
    sctx: String,
}

impl<T: PSQ> From<&Node<T>> for NodeDescriptor {
    fn from(value: &Node<T>) -> Self {
        value.descriptor.clone()
    }
}
