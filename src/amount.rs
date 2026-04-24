//! PIV amount parsing and formatting.
//!
//! All amounts are carried internally as `u64` satoshis (1 PIV = 10^8 sat).

use crate::params::COIN;

/// Parse a PIV amount string (e.g. `"1.23456789"`) into satoshis.
///
/// Uses exact integer arithmetic — no floating point conversion — so round-trip
/// parsing preserves every satoshi. Maximum 8 decimal places; more returns an error.
pub fn parse_piv_to_sat(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty amount".into());
    }

    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 2 {
        return Err("Invalid amount format".into());
    }

    let integer_part: u64 = parts[0].parse().map_err(|_| "Invalid amount")?;

    let fractional_sat = if parts.len() == 2 {
        let frac = parts[1];
        if frac.len() > 8 {
            return Err("Too many decimal places (max 8)".into());
        }
        if frac.is_empty() {
            0u64
        } else {
            let frac_val: u64 = frac.parse().map_err(|_| "Invalid decimal")?;
            frac_val * 10u64.pow(8 - frac.len() as u32)
        }
    } else {
        0
    };

    integer_part
        .checked_mul(COIN)
        .and_then(|v| v.checked_add(fractional_sat))
        .ok_or_else(|| "Amount overflow".to_string())
}

/// Format a satoshi amount as a PIV string, always with 8 decimal places.
pub fn format_sat_to_piv(sat: u64) -> String {
    let integer = sat / COIN;
    let fractional = sat % COIN;
    format!("{}.{:08}", integer, fractional)
}
