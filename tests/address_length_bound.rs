//! Addresses arrive from a JavaScript caller, which means ultimately from a
//! text field, so their length is an input to be attacked rather than a value
//! to be believed.
//!
//! Base58 decoding is quadratic: each digit multiplies a growing big-integer
//! accumulator. A 100,000-character paste is roughly 10^10 operations, which
//! took over a minute to refuse, on functions sitting directly behind an
//! address field. Nothing past the ceiling can be a valid address however long
//! it is decoded for, so length is checked before decoding rather than after.
//!
//! The timing assertion is the one that matters: without the guard these
//! inputs are still refused, eventually, so a plain `is_err()` would pass and
//! prove nothing.

use pivx_wallet_kit::keys;
use pivx_wallet_kit::transparent::coldstake::{
    decode_owner_address, decode_staking_address, encode_staking_address,
};
use std::time::{Duration, Instant};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn refused_quickly(what: &str, len: usize, refuse: impl FnOnce() -> bool) {
    let started = Instant::now();
    assert!(refuse(), "{what}: a {len}-character address must be refused");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(250),
        "{what}: a {len}-character address took {elapsed:?} to refuse; the length guard is \
         not bounding the decode"
    );
}

#[test]
fn an_overlong_address_is_rejected_quickly() {
    for len in [10_000usize, 200_000] {
        for prefix in ["D", "S"] {
            let huge = format!("{prefix}{}", "q".repeat(len));
            refused_quickly("address_to_p2pkh_script", len, || {
                keys::address_to_p2pkh_script(&huge).is_err()
            });
            refused_quickly("decode_generic_address", len, || {
                keys::decode_generic_address(&huge).is_err()
            });
            refused_quickly("decode_owner_address", len, || decode_owner_address(&huge).is_err());
            refused_quickly("decode_staking_address", len, || {
                decode_staking_address(&huge).is_err()
            });
        }
    }
}

#[test]
fn addresses_of_a_plausible_length_still_work() {
    // The guard must not be so tight that it refuses real addresses.
    let owner = keys::get_transparent_address(TEST_MNEMONIC).unwrap();
    assert!(owner.len() <= 40, "a real address is short: {} chars", owner.len());
    assert!(keys::address_to_p2pkh_script(&owner).is_ok());
    assert!(keys::decode_generic_address(&owner).is_ok());
    assert!(decode_owner_address(&owner).is_ok());

    let staker = encode_staking_address(&[0x42; 20]);
    assert!(staker.len() <= 40, "a real address is short: {} chars", staker.len());
    assert!(decode_staking_address(&staker).is_ok());
}
