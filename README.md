# Rust tools for Ledger Zcash app

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Github Actions](https://github.com/Zondax/ledger-zcash-tools/actions/workflows/main.yaml/badge.svg)](https://github.com/Zondax/ledger-zcash-tools)

This package provides a basic Rust tooling to build and sign transactions using the Crypto App running in a Ledger Nano S/X
devices

## Build

- Install rust using the instructions [here](https://www.rust-lang.org/tools/install)
- To build run:

```shell script
cargo build
```

## Run Tests

To run the tests

- Initialize your device with the test mnemonic. More
  info [here](https://github.com/zondax/ledger-zcash#how-to-prepare-your-development-device)
- run tests using:

```shell script
cargo test --all
```
