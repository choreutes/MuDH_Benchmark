# Benchmarking Tool for MuDH and pqMuDH

This repository contains the source code for the benchmarks used in the paper “Efficiency Improvements for Signal’s Handshake Protocol”.
It compares the execution times of the MuDH and pqMuDH key exchange protocols from the paper with the ones of Signal’s X3DH and PQXDH protocols.

The paper can be found on the IACR preprint server under [2025/1843](https://ia.cr/2025/1843). It is joint work with my collaborators Barbara Jiabao Benedikt ([ORCID](https://orcid.org/0009-0000-5317-0570)), Sebastian Clermont ([ORCID](https://orcid.org/0009-0005-9436-1417)) and Marc Fischlin ([ORCID](https://orcid.org/0000-0003-0597-8297)).

## Setup

To build the benchmark you need a working Rust programming environment.
If you are using the Nix package manager, you can use the provided ``flake.nix`` to setup such an environment with the exact software versions that we have used.

Navigate to the root directory of the repository and run
```
cargo build --release
```
This will automatically download and build all dependencies of the benchmark and the benchmark itself.
The resulting binaries will appear inside a ``target/release/`` directory next to the ``src/`` directory.

## Usage

After successfully completing the build, there will be an executable file ``benchmark`` inside the ``target/release/`` directory.
Execute it to start a benchmark run.
The program accepts three command line options to configure the protocols:

- ``-k``/``--kyber``:
  Enables the use of a Kyber KEM ciphertext during the handshake, effectively switching between X3DH/MuDH and PQXDH/pqMuDH.
- ``-o``/``--opkb``:
  Enables the use of a one-time prekey on Bob’s side of the handshake.
- ``-c <N>``/``--count <N>``:
  Determines the number of handshakes to be executed during the benchmark.