use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use uuid::Uuid;

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
pub const SUPPRESSION_HMAC_KEY_ENV: &str = "SOCIALNAME_SUPPRESSION_HMAC_KEY_HEX";
pub const EXPECTED_RESTORE_LEDGER_ID_ENV: &str = "SOCIALNAME_EXPECTED_RESTORE_LEDGER_ID";

#[derive(Clone, PartialEq, Eq)]
pub struct SuppressionHmacKey([u8; 32]);

impl SuppressionHmacKey {
    pub fn from_hex(value: &str) -> Result<Self, ConfigError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ConfigError::new(
                SUPPRESSION_HMAC_KEY_ENV,
                "must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        let decoded = hex::decode(value).map_err(|_| {
            ConfigError::new(
                SUPPRESSION_HMAC_KEY_ENV,
                "must be exactly 64 lowercase hexadecimal characters",
            )
        })?;
        let key = decoded.try_into().map_err(|_| {
            ConfigError::new(
                SUPPRESSION_HMAC_KEY_ENV,
                "must be exactly 64 lowercase hexadecimal characters",
            )
        })?;
        Ok(Self(key))
    }

    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SuppressionHmacKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SuppressionHmacKey([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    bind_address: SocketAddr,
    request_timeout: Duration,
    maximum_body_bytes: usize,
    maximum_in_flight: usize,
    suppression_hmac_key: Option<SuppressionHmacKey>,
    expected_restore_ledger_id: Option<Uuid>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: DEFAULT_BIND_ADDRESS,
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            maximum_body_bytes: DEFAULT_MAXIMUM_BODY_BYTES,
            maximum_in_flight: DEFAULT_MAXIMUM_IN_FLIGHT,
            suppression_hmac_key: None,
            expected_restore_ledger_id: None,
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
            suppression_hmac_key: None,
            expected_restore_ledger_id: None,
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
        let mut config = Self::new(
            bind_address,
            Duration::from_millis(request_timeout_ms),
            maximum_body_bytes,
            maximum_in_flight,
        )?;
        let key = lookup(SUPPRESSION_HMAC_KEY_ENV)?.ok_or_else(|| {
            ConfigError::new(
                SUPPRESSION_HMAC_KEY_ENV,
                "is required for suppression-aware managed operation",
            )
        })?;
        config.suppression_hmac_key = Some(SuppressionHmacKey::from_hex(&key)?);
        config.expected_restore_ledger_id = lookup(EXPECTED_RESTORE_LEDGER_ID_ENV)?
            .map(|value| {
                Uuid::parse_str(&value).map_err(|_| {
                    ConfigError::new(EXPECTED_RESTORE_LEDGER_ID_ENV, "must be a canonical UUID")
                })
            })
            .transpose()?;
        Ok(config)
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

    #[must_use]
    pub fn suppression_hmac_key(&self) -> Option<&SuppressionHmacKey> {
        self.suppression_hmac_key.as_ref()
    }

    #[must_use]
    pub const fn expected_restore_ledger_id(&self) -> Option<Uuid> {
        self.expected_restore_ledger_id
    }

    #[must_use]
    pub fn with_suppression_hmac_key(mut self, key: SuppressionHmacKey) -> Self {
        self.suppression_hmac_key = Some(key);
        self
    }

    #[must_use]
    pub const fn with_expected_restore_ledger_id(mut self, id: Uuid) -> Self {
        self.expected_restore_ledger_id = Some(id);
        self
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
        let config = ServerConfig::from_lookup(|name| {
            Ok((name == SUPPRESSION_HMAC_KEY_ENV).then(|| "11".repeat(32)))
        })
        .unwrap();
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
                SUPPRESSION_HMAC_KEY_ENV => Some("22".repeat(32)),
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
    fn suppression_key_is_required_and_redacted() {
        let missing = ServerConfig::from_lookup(|_| Ok(None)).unwrap_err();
        assert!(missing.to_string().contains(SUPPRESSION_HMAC_KEY_ENV));
        let secret = "private-suppression-secret";
        let invalid = SuppressionHmacKey::from_hex(secret).unwrap_err();
        assert!(!invalid.to_string().contains(secret));
        let key = SuppressionHmacKey::from_hex(&"33".repeat(32)).unwrap();
        assert!(!format!("{key:?}").contains(&"33".repeat(32)));
    }

    #[test]
    fn restore_ledger_id_is_optional_but_strict_when_present() {
        let expected = Uuid::parse_str("00000000-0000-0000-0000-000000000123").unwrap();
        let config = ServerConfig::from_lookup(|name| {
            Ok(match name {
                SUPPRESSION_HMAC_KEY_ENV => Some("44".repeat(32)),
                EXPECTED_RESTORE_LEDGER_ID_ENV => Some(expected.to_string()),
                _ => None,
            })
        })
        .unwrap();
        assert_eq!(config.expected_restore_ledger_id(), Some(expected));
        let invalid = ServerConfig::from_lookup(|name| {
            Ok(match name {
                SUPPRESSION_HMAC_KEY_ENV => Some("44".repeat(32)),
                EXPECTED_RESTORE_LEDGER_ID_ENV => Some("private-invalid-value".to_owned()),
                _ => None,
            })
        })
        .unwrap_err();
        assert!(invalid.to_string().contains(EXPECTED_RESTORE_LEDGER_ID_ENV));
        assert!(!invalid.to_string().contains("private-invalid-value"));
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
