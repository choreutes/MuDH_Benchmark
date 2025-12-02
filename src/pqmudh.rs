use crate::GROUP_ORDER_BYTES;
use crate::derive_keys;

use curve25519_dalek::{
    EdwardsPoint,
    MontgomeryPoint,
};

use curve25519_dalek::traits::Identity;

use libsignal_protocol::{
    AliceSignalProtocolParameters,
    SignalProtocolError,
};

use num_bigint::BigUint;

use rand::{Rng, CryptoRng};

use sha2::{
    Sha256,
    Digest,
};

pub fn pqmudh_alice<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    rng: &mut R
) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    let mut secrets = Vec::with_capacity(32 * 3);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    // This cannot be turned into a constant
    // because the coversion function is not declared constant.
    let group_order: BigUint = BigUint::from_bytes_le(&GROUP_ORDER_BYTES);

    // Initialize a Sha2 hasher object to compute randomizers.
    let mut hasher = Sha256::new();

    // Extract Alice's public identity key.
    let ik_a_public_bytes: &[u8; 32] = parameters
        .our_identity_key_pair()
        .public_key()
        .public_key_bytes()
        .try_into()
        .expect("Public keys should always have the correct length");

    // Feed Alice's public identity key into the hasher.
    hasher.update(ik_a_public_bytes);

    // Extract Bob's public identity key.
    let ik_b_bytes: &[u8; 32] = parameters
        .their_identity_key()
        .public_key()
        .public_key_bytes()
        .try_into()
        .expect("Public keys should always have the correct length");

    // Feed Bob's public identity key into the hasher.
    hasher.update(ik_b_bytes);

    // Bob's identity key also needs to be converted into Edwards form.
    // We arbitrarily choose the positive sign for the curve point.
    let ik_b: EdwardsPoint = MontgomeryPoint(*ik_b_bytes)
        .to_edwards(0)
        .expect("Conversion to Edwards points should be possible");

    // Extract Alice's public ephemeral key.
    let ek_a_public_bytes: &[u8; 32] = parameters
        .our_base_key_pair()
        .public_key
        .public_key_bytes()
        .try_into()
        .expect("Public keys should always have the correct length");

    // Feed Alice's public ephemeral key into the hasher.
    hasher.update(ek_a_public_bytes);

    // Extract Bob's public signed pre-key.
    let spk_b_bytes: &[u8; 32] = parameters
        .their_signed_pre_key()
        .public_key_bytes()
        .try_into()
        .expect("Public keys should always have the correct length");

    // Feed Bob's public signed pre-key to the hasher.
    hasher.update(spk_b_bytes);

    // Bob's signed pre-key also needs to be converted into Edwards form.
    // We arbitrarily choose the positive sign for the curve point.
    let spk_b: EdwardsPoint = MontgomeryPoint(*spk_b_bytes)
        .to_edwards(0)
        .expect("Conversion to Edwards points should be possible");

    // Extract Alice's private identity key in byte form.
    let ik_a_private_vec = parameters
        .our_identity_key_pair()
        .private_key()
        .serialize();
    let ik_a_private_bytes: &[u8; 32] = ik_a_private_vec
        .as_slice()
        .try_into()
        .expect("Private keys should always have the correct length");

    let ik_a_private_num: BigUint = BigUint::from_bytes_le(ik_a_private_bytes);

    // Extract Alice's private ephemeral key in byte form.
    let ek_a_private_vec = parameters
        .our_base_key_pair()
        .private_key
        .serialize();
    let ek_a_private_bytes: &[u8; 32] = ek_a_private_vec
        .as_slice()
        .try_into()
        .expect("Private keys should always have the correct length");

    let ek_a_private_num: BigUint = BigUint::from_bytes_le(ek_a_private_bytes);

    let mut exp_4_opt: Option<Vec<u8>> = None;
    let mut opk_b_opt: Option<EdwardsPoint> = None;

    if let Some(opk_b_temp) = parameters.their_one_time_pre_key() {
        let opk_b_bytes: &[u8; 32] = opk_b_temp
            .public_key_bytes()
            .try_into()
            .expect("Public keys should always have the correct length");

        hasher.update(opk_b_bytes);

        let alpha_4_bytes: [u8; 32] = hasher.clone().chain_update([4u8]).finalize().into();
        let exp_4_num: BigUint = (BigUint::from_bytes_le(&alpha_4_bytes) * &ek_a_private_num) % &group_order;
        let mut exp_4_bytes: Vec<u8> = exp_4_num.to_bytes_le();

        exp_4_bytes.resize(32, 0u8);

        assert_eq!(exp_4_bytes.len(), 32);

        exp_4_opt = Some(exp_4_bytes);

        let opk_b: EdwardsPoint = MontgomeryPoint(*opk_b_bytes)
            .to_edwards(0)
            .expect("Conversion to Edwards points should be possible");

        opk_b_opt = Some(opk_b);
    }

    // Compute randomizers from the hash function
    let alpha_1_bytes: [u8; 32] = hasher.clone().chain_update([1u8]).finalize().into();
    let alpha_2_bytes: [u8; 32] = hasher.clone().chain_update([2u8]).finalize().into();
    let alpha_3_bytes: [u8; 32] = hasher.clone().chain_update([3u8]).finalize().into();

    // Convert randomizers to numbers and multiply by private keys
    let mut exp_1_num: BigUint = BigUint::from_bytes_le(&alpha_1_bytes) * &ik_a_private_num;
    let mut exp_2_num: BigUint = BigUint::from_bytes_le(&alpha_2_bytes) * &ek_a_private_num;
    let exp_3_num: BigUint = BigUint::from_bytes_le(&alpha_3_bytes) * &ek_a_private_num;

    // Optimize calculation, since exp_1 and exp_3 affect the same public key of Bob
    exp_1_num += exp_3_num;

    // Reduce exponents by the order of the group
    exp_1_num %= &group_order;
    exp_2_num %= &group_order;

    let mut exp_1_bytes: Vec<u8> = exp_1_num.to_bytes_le();
    let mut exp_2_bytes: Vec<u8> = exp_2_num.to_bytes_le();
    // let mut exp_3_bytes: Vec<u8> = exp_3_num.to_bytes_le();

    exp_1_bytes.resize(32, 0u8);
    exp_2_bytes.resize(32, 0u8);
    // exp_3_bytes.resize(32, 0u8);

    assert_eq!(exp_1_bytes.len(), 32);
    assert_eq!(exp_2_bytes.len(), 32);
    // assert_eq!(exp_3_bytes.len(), 32);

    // Initialize shared secret to neutral element before starting computation.
    let mut shared_point = EdwardsPoint::identity();

    // Iterate over individual bits of the calculated exponents,
    // starting with the most significant bit.
    for i in (0..31).rev() {
        for j in (0..7).rev() {
            if (exp_1_bytes[i] & 1u8 << j) != 0u8 {
                shared_point += spk_b;
            }

            if (exp_2_bytes[i] & 1u8 << j) != 0u8 {
                shared_point += ik_b;
            }

            // if (exp_3_bytes[i] & 1u8 << j) != 0u8 {
            //     shared_point += spk_b;
            // }

            if let Some(ref exp_4_bytes) = exp_4_opt {
                if (exp_4_bytes[i] & 1u8 << j) != 0u8 {
                    shared_point += opk_b_opt.unwrap();
                }
            }

            shared_point += shared_point;
        }
    }

    secrets.extend_from_slice(shared_point.compress().as_bytes());

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
