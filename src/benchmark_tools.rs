/* SPDX-FileCopyrightText:  © 2025 Tobias Schmalz <github@choreutes.de>
 * SPDX-License-Identifier: MIT
 *
 * benchmark_tools.rs
 *
 * Defines some convenient helper functions.
 */

use crate::pqxdh_alice_plain;
use crate::pqmudh_alice;
use crate::pqmudh_alice_with_prep;

use libsignal_protocol::{
    AliceSignalProtocolParameters,
    IdentityKey,
    IdentityKeyPair,
    KeyPair,
    PublicKey,
};

use rand::{Rng, CryptoRng};

use std::hint::black_box;

use std::time::Instant;

pub fn setup_alice_parameters<R: Rng + CryptoRng>(rng: &mut R) -> AliceSignalProtocolParameters {
    // Generate Alice's session parameters:
    // Alice has two predetermined keypairs:
    // - identity keypair (IK_A)
    // - base keypair / ephemeral keypair (EK_A)
    // Additionally a ratchet keypair will be generated on the fly,
    // which is not important to us.
    let alice_identity_keypair: IdentityKeyPair = KeyPair::generate(rng).into();
    let alice_base_keypair: KeyPair = KeyPair::generate(rng);

    // Generate Bob's session parameters:
    // Bob has four predetermined keypairs:
    // - identity keypair (IK_B)
    // - signed pre-keypair (SPK_B)
    // - one time pre-keypair (OPK_B)
    // - ratchet keypair which is not important for pure X3DH
    let bob_identity_key: IdentityKey = KeyPair::generate(rng).public_key.into();
    let bob_signed_pre_key: PublicKey = KeyPair::generate(rng).public_key;
    // let bob_one_time_pre_key: PublicKey = KeyPair::generate(rng).public_key;
    let bob_ratchet_key: PublicKey = KeyPair::generate(rng).public_key;

    AliceSignalProtocolParameters::new(
        alice_identity_keypair,
        alice_base_keypair,
        bob_identity_key,
        bob_signed_pre_key,
        bob_ratchet_key
    )
}

pub fn one_shot_benchmark<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    rng: &mut R
) -> (u32, u32, u32, u32) {
    let libsignal_start = Instant::now();

    let benchmark_record = libsignal_protocol::initialize_alice_session_record(
        parameters,
        rng
    ).expect("record creation should succeed");

    // Prevent compiler from optimizing away the function call
    black_box(benchmark_record);

    let libsignal_time: u32 = libsignal_start
        .elapsed()
        .as_micros()
        .try_into()
        .expect("Computation took longer than an hour...");

    let pqxdh_plain_start = Instant::now();

    let pqxdh_plain_key = pqxdh_alice_plain(parameters, rng).expect("pqXDH key exchange should succeed");

    // Prevent compiler from optimizing away the function call
    black_box(pqxdh_plain_key);

    let pqxdh_plain_time: u32 = pqxdh_plain_start
        .elapsed()
        .as_micros()
        .try_into()
        .expect("Computation took longer than an hour...");

    let pqmudh_start = Instant::now();

    let pqmudh_key = pqmudh_alice(parameters, rng).expect("pqMuDH key exchange should succeed");

    // Prevent compiler from optimizing away the function call
    black_box(pqmudh_key);

    let pqmudh_time: u32 = pqmudh_start
        .elapsed()
        .as_micros()
        .try_into()
        .expect("Computation took longer than an hour...");

    let pqmudh_prep_start = Instant::now();

    let pqmudh_prep_key = pqmudh_alice_with_prep(parameters, rng).expect("pqMuDH key exchange with prep. should succeed");

    // Prevent compiler from optimizing away the function call
    black_box(pqmudh_prep_key);

    let pqmudh_prep_time: u32 = pqmudh_prep_start
        .elapsed()
        .as_micros()
        .try_into()
        .expect("Computation took longer than an hour...");

    (
        libsignal_time,
        pqxdh_plain_time,
        pqmudh_time,
        pqmudh_prep_time
    )
}

pub fn vector_stats(vec: &Vec<f64>, len: &f64) -> (f64, f64) {
    let mean: f64 = vec.iter().sum::<f64>() / len;
    let variance: f64 = vec.iter().fold(0.0f64, |acc, val| acc + f64::powi(val - mean, 2)) / (len - 1.0f64);
    let std_dev: f64 = variance.sqrt();

    (mean, std_dev)
}
