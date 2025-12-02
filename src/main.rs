mod benchmark_tools;
mod key_derivation;
mod pqmudh;
mod pqmudh_prep;
mod pqxdh;

pub use benchmark_tools::one_shot_benchmark;
pub use key_derivation::derive_keys;
pub use pqmudh::pqmudh_alice;
pub use pqmudh_prep::pqmudh_alice_with_prep;
pub use pqxdh::pqxdh_alice_plain;

use benchmark_tools::{setup_alice_parameters, vector_stats};

use clap::Parser;

use rand::SeedableRng;
use rand::rngs;

use libsignal_protocol::{
    AliceSignalProtocolParameters,
    KeyPair,
    PublicKey,
};
use libsignal_protocol::kem;

const GROUP_ORDER_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Parser)]
struct Cli {
    /// The number of benchmarks to run and average
    #[arg(short, long, default_value = "1")]
    count: u32,
    /// Use Kyber1024 key encapsulation during key exchange
    #[arg(short, long, default_value = "false")]
    kyber: bool,
    /// Use one-time prekey for Bob during key exchange
    #[arg(short, long, default_value = "false")]
    opkb: bool,
    /// Enable verbose mode
    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

fn main() {
    let args = Cli::parse();

    let mut rng = rngs::StdRng::from_os_rng();

    if args.count == 1 {
        let parameters: AliceSignalProtocolParameters = setup_alice_parameters(&mut rng);

        let (signal, plain, fast, faster) = one_shot_benchmark(&parameters, &mut rng);

        if args.verbose {
            println!{"Full libsignal session setup took {} µs.", signal};
            println!{"Plain X3DH key exchange took {} µs.", plain};
            println!{"Fast X3DH key exchange took {} µs.", fast};
            println!{"Fast X3DH key exchange with pre-computation took {} µs.", faster};
        } else {
            println!("{}", signal);
            println!("{}", plain);
            println!("{}", fast);
            println!("{}", faster);
        }
    } else if args.count > 1 {
        // This cannot fail if run on a CPU with at least 32 bits.
        let count: usize = args.count.try_into().expect("Number of runs should not be too large");

        // Running times with Kyber encapsulation
        let mut signal_pqxdh_results: Vec<f64> = Vec::with_capacity(count);
        let mut plain_pqxdh_results: Vec<f64> = Vec::with_capacity(count);
        let mut pqmudh_results: Vec<f64> = Vec::with_capacity(count);
        let mut pqmudh_prep_results: Vec<f64> = Vec::with_capacity(count);

        for _ in 1..args.count {
            // Generate parameters without one-time prekey and Kyber
            let mut parameters: AliceSignalProtocolParameters = setup_alice_parameters(&mut rng);

            if args.kyber {
                // Generate a Kyber key for Bob
                let bob_kem_key: kem::PublicKey = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng).public_key;

                // Add the Kyber1024 key to parameters
                parameters.set_their_kyber_pre_key(&bob_kem_key);
            }

            if args.opkb {
                // Generate a one-time prekey for Bob
                let opkb: PublicKey = KeyPair::generate(&mut rng).public_key;

                // Add the one-time prekey to the parameters
                parameters.set_their_one_time_pre_key(opkb);
            }

            // Run benchmark again, this time with Kyber
            let (signal_pqxdh, plain_pqxdh, pqmudh, pqmudh_prep) = one_shot_benchmark(&parameters, &mut rng);

            // Insert results
            signal_pqxdh_results.push(signal_pqxdh.into());
            plain_pqxdh_results.push(plain_pqxdh.into());
            pqmudh_results.push(pqmudh.into());
            pqmudh_prep_results.push(pqmudh_prep.into());
        }

        let count: f64 = args.count.into();

        let (signal_pqxdh_mean, signal_pqxdh_std_dev) = vector_stats(&signal_pqxdh_results, &count);
        let (plain_pqxdh_mean, plain_pqxdh_std_dev) = vector_stats(&plain_pqxdh_results, &count);
        let (pqmudh_mean, pqmudh_std_dev) = vector_stats(&pqmudh_results, &count);
        let (pqmudh_prep_mean, pqmudh_prep_std_dev) = vector_stats(&pqmudh_prep_results, &count);

        println!{"Full libsignal session setup took {:.1}({:.1}) µs on average.", signal_pqxdh_mean, signal_pqxdh_std_dev};
        println!{"Plain pqXDH key exchange took {:.1}({:.1}) µs on average.", plain_pqxdh_mean, plain_pqxdh_std_dev};
        println!{"pqMuDH key exchange took {:.1}({:.1}) µs on average.", pqmudh_mean, pqmudh_std_dev};
        println!{"pqMuDH key exchange with preprocessing took {:.1}({:.1}) µs on average.", pqmudh_prep_mean, pqmudh_prep_std_dev};
    }
}
