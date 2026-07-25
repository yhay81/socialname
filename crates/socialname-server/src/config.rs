use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

const DEFAULT_BIND_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8_080);
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAXIMUM_BODY_BYTES: usize = 256 * 1_024;
const DEFAULT_MAXIMUM_IN_FLIGHT: usize = 128;

const MINIMUM_REQUEST_TIMEOUT_MS: u64 = 100;
const MAXIMUM_REQUEST_TIMEOUT_MS: u64 = 120_000;
const MINIMUM_BODY_BYTES: usize = 1_024;
const MAXIMUM_BODY_BYTES: usize = 1_024 * 1_024;
const MAXIMUM_IN_FLIGHT: usize = 1_024;

pub const BIND_ENV: &str = "SOCIALNAME_SERVER_BIND";
pub const REQUEST_TIMEOUT_ENV: &str = "SOCIALNAME_SERVER_REQUEST_TIMEOUT_MS";
pub const MAXIMUM_BODY_BYTES_ENV: &str = "SOCIALNAME_SERVER_MAXIMUM_BODY_BYTES";
pub const MAXIMUM_IN_FLIGHT_ENV: &str = "SOCIALNAME_SERVER_MAXIMUM_IN_FLIGHT";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    bind_address: SocketAddr,
    request_timeout: Duration,
    maximum_body_bytes: usize,
    maximum_in_flight: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: DEFAULT_BIND_ADDRESS,
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            maximum_body_bytes: DEFAULT_MAXIMUM_BODY_BYTES,
            maximum_in_flight: DEFAULT_MAXIMUM_IN_FLIGHT,
        }
    }
}

impl ServerConfig {
    pub fn new(
        bind_address: SocketAddr,
        request_timeout: Duration,
        maximum_body_bytes: usize,
        maximum_in_flight: usize,
    ) -> Result<Self, ConfigError> {
        if request_timeout.as_nanos() % 1_000_000 != 0 {
            return Err(ConfigError::new(
                REQUEST_TIMEOUT_ENV,
                "must be representable as whole milliseconds",
            ));
        }
        let request_timeout_ms = u64::try_from(request_timeout.as_millis()).map_err(|_| {
            ConfigError::new(
                REQUEST_TIMEOUT_ENV,
                "must be representable as whole milliseconds",
            )
        })?;
        if !(MINIMUM_REQUEST_TIMEOUT_MS..=MAXIMUM_REQUEST_TIMEOUT_MS).contains(&request_timeout_ms)
        {
            return Err(ConfigError::new(
                REQUEST_TIMEOUT_ENV,
                "must be between 100 and 120000 milliseconds",
            ));
        }
        if !(MINIMUM_BODY_BYTES..=MAXIMUM_BODY_BYTES).contains(&maximum_body_bytes) {
            return Err(ConfigError::new(
                MAXIMUM_BODY_BYTES_ENV,
                "must be between 1024 and 1048576 bytes",
            ));
        }
        if !(1..=MAXIMUM_IN_FLIGHT).contains(&maximum_in_flight) {
            return Err(ConfigError::new(
                MAXIMUM_IN_FLIGHT_ENV,
                "must be between 1 and 1024",
            ));
        }
        Ok(Self {
            bind_address,
            request_timeout,
            maximum_body_bytes,
            maximum_in_flight,
        })
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| match env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => {
                Err(ConfigError::new(name, "must contain valid Unicode text"))
            }
        })
    }

    fn from_lookup(
        mut lookup: impl FnMut(&'static str) -> Result<Option<String>, ConfigError>,
    ) -> Result<Self, ConfigError> {
        let defaults = Self::default();
        let bind_address = parse_or_default(
            &mut lookup,
            BIND_ENV,
            defaults.bind_address,
            "must be a socket address such as 127.0.0.1:8080",
        )?;
        let request_timeout_ms = parse_or_default(
            &mut lookup,
            REQUEST_TIMEOUT_ENV,
            DEFAULT_REQUEST_TIMEOUT_MS,
            "must be an integer number of milliseconds",
        )?;
        let maximum_body_bytes = parse_or_default(
            &mut lookup,
            MAXIMUM_BODY_BYTES_ENV,
            defaults.maximum_body_bytes,
            "must be an integer number of bytes",
        )?;
        let maximum_in_flight = parse_or_default(
            &mut lookup,
            MAXIMUM_IN_FLIGHT_ENV,
            defaults.maximum_in_flight,
            "must be an integer request count",
        )?;
        Self::new(
            bind_address,
            Duration::from_millis(request_timeout_ms),
            maximum_body_bytes,
            maximum_in_flight,
        )
    }

    #[must_use]
    pub const fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    #[must_use]
    pub const fn maximum_body_bytes(&self) -> usize {
        self.maximum_body_bytes
    }

    #[must_use]
    pub const fn maximum_in_flight(&self) -> usize {
        self.maximum_in_flight
    }
}

fn parse_or_default<T>(
    lookup: &mut impl FnMut(&'static str) -> Result<Option<String>, ConfigError>,
    name: &'static str,
    default: T,
    reason: &'static str,
) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    match lookup(name)? {
        Some(value) => value.parse().map_err(|_| ConfigError::new(name, reason)),
        None => Ok(default),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid {variable}: {reason} (the supplied value is omitted)")]
pub struct ConfigError {
    variable: &'static str,
    reason: &'static str,
}

impl ConfigError {
    const fn new(variable: &'static str, reason: &'static str) -> Self {
        Self { variable, reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_bind_only_to_loopback_with_bounded_resources() {
        let config = ServerConfig::from_lookup(|_| Ok(None)).unwrap();
        assert_eq!(config.bind_address(), "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.request_timeout(), Duration::from_secs(30));
        assert_eq!(config.maximum_body_bytes(), 262_144);
        assert_eq!(config.maximum_in_flight(), 128);
    }

    #[test]
    fn explicit_values_are_parsed_without_implicit_public_binding() {
        let config = ServerConfig::from_lookup(|name| {
            Ok(match name {
                BIND_ENV => Some("127.0.0.1:0".to_owned()),
                REQUEST_TIMEOUT_ENV => Some("5000".to_owned()),
                MAXIMUM_BODY_BYTES_ENV => Some("65536".to_owned()),
                MAXIMUM_IN_FLIGHT_ENV => Some("32".to_owned()),
                _ => None,
            })
        })
        .unwrap();
        assert_eq!(config.bind_address(), "127.0.0.1:0".parse().unwrap());
        assert_eq!(config.request_timeout(), Duration::from_secs(5));
        assert_eq!(config.maximum_body_bytes(), 65_536);
        assert_eq!(config.maximum_in_flight(), 32);
    }

    #[test]
    fn invalid_values_are_omitted_from_errors() {
        let secret = "not-a-socket-secret";
        let error =
            ServerConfig::from_lookup(|name| Ok((name == BIND_ENV).then(|| secret.to_owned())))
                .unwrap_err()
                .to_string();
        assert!(error.contains(BIND_ENV));
        assert!(!error.contains(secret));
    }

    #[test]
    fn zero_or_excessive_limits_are_rejected() {
        assert!(
            ServerConfig::new(
                DEFAULT_BIND_ADDRESS,
                Duration::from_micros(100_001),
                DEFAULT_MAXIMUM_BODY_BYTES,
                DEFAULT_MAXIMUM_IN_FLIGHT,
            )
            .is_err()
        );
        assert!(
            ServerConfig::new(
                DEFAULT_BIND_ADDRESS,
                Duration::from_millis(99),
                DEFAULT_MAXIMUM_BODY_BYTES,
                DEFAULT_MAXIMUM_IN_FLIGHT,
            )
            .is_err()
        );
        assert!(
            ServerConfig::new(
                DEFAULT_BIND_ADDRESS,
                Duration::from_secs(1),
                MAXIMUM_BODY_BYTES + 1,
                DEFAULT_MAXIMUM_IN_FLIGHT,
            )
            .is_err()
        );
        assert!(
            ServerConfig::new(
                DEFAULT_BIND_ADDRESS,
                Duration::from_secs(1),
                DEFAULT_MAXIMUM_BODY_BYTES,
                0,
            )
            .is_err()
        );
    }
}
