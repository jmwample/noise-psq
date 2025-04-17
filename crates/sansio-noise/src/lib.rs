use libcrux_psq::{cred::Authenticator, traits::PSQ};

pub mod noise;
pub mod psk;

#[cfg(test)]
mod test {

    use std::env;
    use std::str::FromStr;
    use std::sync::Once;
    use tracing_subscriber::filter::LevelFilter;

    static INIT_LOGGING: Once = Once::new();

    pub(crate) fn init_subscriber() {
        INIT_LOGGING.call_once(|| {
            let level = env::var("RUST_LOG").unwrap_or("trace".into());
            let lf = LevelFilter::from_str(&level).unwrap();
            tracing_subscriber::fmt().with_max_level(lf).init();
        });
    }
}

struct Protocol<'proto, C, T>
where
    C: Authenticator,
    T: PSQ,
{
    is_initiator: bool,
    psk: psk::PsqProtocol<'proto, C, T>,
    noise: noise::NoiseProtocol,
}
