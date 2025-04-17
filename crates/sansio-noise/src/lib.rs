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
