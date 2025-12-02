use hkdf::Hkdf;
use sha2::Sha256;

pub fn derive_keys(has_kyber: bool, secret_input: &[u8]) -> [u8; 64] {
    let label = if has_kyber {
        b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024".as_slice()
    } else {
        b"WhisperText".as_slice()
    };

    derive_keys_with_label(label, secret_input)
}

fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> [u8; 64] {
    let mut shared_secret = [0; 64];

    Hkdf::<Sha256>::new(None, &secret_input)
        .expand(label, &mut shared_secret)
        .expect("valid length");

    shared_secret
}

