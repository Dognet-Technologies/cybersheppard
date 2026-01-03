// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Type Conversion Utilities
// ============================================================================
// Helper traits and functions for converting between PostgreSQL types
// and Rust native types

use bigdecimal::BigDecimal;
use ipnetwork::IpNetwork;
use std::str::FromStr;

// ============================================================================
// BigDecimal Extensions
// ============================================================================

pub trait BigDecimalExt {
    fn to_f32(&self) -> f32;
    fn to_f64(&self) -> f64;
}

impl BigDecimalExt for BigDecimal {
    fn to_f32(&self) -> f32 {
        self.to_string().parse().unwrap_or(0.0)
    }

    fn to_f64(&self) -> f64 {
        self.to_string().parse().unwrap_or(0.0)
    }
}

impl BigDecimalExt for Option<BigDecimal> {
    fn to_f32(&self) -> f32 {
        self.as_ref()
            .map(|d| d.to_string().parse().unwrap_or(0.0))
            .unwrap_or(0.0)
    }

    fn to_f64(&self) -> f64 {
        self.as_ref()
            .map(|d| d.to_string().parse().unwrap_or(0.0))
            .unwrap_or(0.0)
    }
}

// ============================================================================
// BigDecimal Creation from f32/f64
// ============================================================================

pub trait ToBigDecimal {
    fn to_bigdecimal(&self) -> BigDecimal;
}

impl ToBigDecimal for f32 {
    fn to_bigdecimal(&self) -> BigDecimal {
        BigDecimal::from_str(&self.to_string()).unwrap_or_else(|_| BigDecimal::from(0))
    }
}

impl ToBigDecimal for f64 {
    fn to_bigdecimal(&self) -> BigDecimal {
        BigDecimal::from_str(&self.to_string()).unwrap_or_else(|_| BigDecimal::from(0))
    }
}

impl ToBigDecimal for i32 {
    fn to_bigdecimal(&self) -> BigDecimal {
        BigDecimal::from(*self)
    }
}

// ============================================================================
// IpNetwork Extensions
// ============================================================================

pub trait IpNetworkExt {
    fn to_string_addr(&self) -> String;
    fn ip_string(&self) -> String;
}

impl IpNetworkExt for IpNetwork {
    fn to_string_addr(&self) -> String {
        self.ip().to_string()
    }

    fn ip_string(&self) -> String {
        self.ip().to_string()
    }
}

impl IpNetworkExt for Option<IpNetwork> {
    fn to_string_addr(&self) -> String {
        self.as_ref()
            .map(|ip| ip.ip().to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string())
    }

    fn ip_string(&self) -> String {
        self.to_string_addr()
    }
}

// ============================================================================
// String to IpNetwork
// ============================================================================

pub trait ToIpNetwork {
    fn to_ipnetwork(&self) -> Option<IpNetwork>;
}

impl ToIpNetwork for String {
    fn to_ipnetwork(&self) -> Option<IpNetwork> {
        IpNetwork::from_str(self).ok()
    }
}

impl ToIpNetwork for &str {
    fn to_ipnetwork(&self) -> Option<IpNetwork> {
        IpNetwork::from_str(self).ok()
    }
}
