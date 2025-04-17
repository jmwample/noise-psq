# Noise + PQ PSK


## PSK Options


## Examples

in `/examples`

- `psk.rs` - psk only example equivalent to the one in libcrux psq to make sure that works as expected
- `node_to_node.rs` - example of mutually authenticating nodes that establish a noise XKpsk3 tunnel.


questions:

- What is the intention behind the sctx and handle?

- when connecting with XKpsk3 are the keys used POST psk exchange for the noise handshake supposed
to use the same keys as the PSK step or should those be ephemeral one off session keys generated
at time of use?

- Is there any reason including extra data in the encrypted portion of initiator and responder messages
is bad for security? For example allow the client to send an indicator of IKpsk2 vs XKpsk3 as part of the
PSK that the server acknowledges before proceeding. Obviously those messaegs are not forward secret.

