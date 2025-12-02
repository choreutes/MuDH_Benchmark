/* SPDX-FileCopyrightText:  © 2025 Tobias Schmalz <github@choreutes.de>
 * SPDX-License-Identifier: MIT
 *
 * pqxdh.rs
 *
 * Reimplementation of Signal's pqXDH key exchange protocol
 * without final session setup.
 */

use crate::derive_keys;

use libsignal_protocol::{
    AliceSignalProtocolParameters,
    SignalProtocolError,
};

use rand::{Rng, CryptoRng};

// This is the basic X3DH key exchange as implemented in libsignal.
// We have left out the parts related to building a valid session state,
// as this lies outside the scope of this work.
pub fn pqxdh_alice_plain<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    rng: &mut R
) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let our_base_private_key = parameters.our_base_key_pair().private_key;

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_signed_pre_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?,
    );

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        secrets
            .extend_from_slice(&our_base_private_key.calculate_agreement(their_one_time_prekey)?);
    }

    let _kyber_ciphertext = parameters
        .their_kyber_pre_key()
        .map(|kyber_public| {
            let (ss, ct) = kyber_public.encapsulate(rng)?;
            secrets.extend_from_slice(ss.as_ref());
            Ok::<_, SignalProtocolError>(ct)
        })
        .transpose()?;
    let has_kyber = parameters.their_kyber_pre_key().is_some();

    let shared_secret: [u8; 64] = derive_keys(has_kyber, &secrets);

    Ok(shared_secret)
}
