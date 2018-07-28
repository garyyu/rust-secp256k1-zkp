[![Build Status](https://travis-ci.org/garyyu/rust-secp256k1-zkp.png?branch=master)](https://travis-ci.org/garyyu/rust-secp256k1-zkp)

### rust-secp256k1

This is a rust wrapper around [secp256k1: https://github.com/bitcoin/secp256k1](https://github.com/bitcoin/secp256k1).

`secp256k1` is a Optimized C library for EC operations on curve secp256k1, its [main contributors](https://github.com/bitcoin/secp256k1/graphs/contributors) include:
* [Peter Wuille](https://www.linkedin.com/in/pieterwuille), Co-founder and Core Tech Engineer of Blockstream. 
* [Gregory Maxwell](https://github.com/gmaxwell), a Bitcoin Core developer, Co-Founder and CTO of Blockstream ([resigned](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-January/015586.html) from Blockstream 2017 Nov.).
* [Andrew Poelstra](https://www.linkedin.com/in/andrew-poelstra-958a75106/), Mathematician at Blockstream.
* and all other around fifty contributors.
`secp256k1` is still actively maintained.


This Rust library:
* exposes type-safe Rust bindings for all `libsecp256k1` functions
* implements key generation
* implements deterministic nonce generation via RFC6979
* implements many unit tests, adding to those already present in `libsecp256k1`
* makes no allocations (except in unit tests) for efficiency and use in freestanding implementations

### Documents
* [Rustdoc of Crate _secp256k1_](https://www.wpsoftware.net/rustdoc/secp256k1/)
* [Wiki of This Library](https://github.com/garyyu/rust-secp256k1-zkp/wiki)


