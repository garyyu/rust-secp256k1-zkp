[![Build Status](https://travis-ci.org/garyyu/rust-secp256k1-zkp.png?branch=master)](https://travis-ci.org/garyyu/rust-secp256k1-zkp)

### rust-secp256k1

This is a rust wrapper around **secp256k1**, with interesting [Wiki](https://github.com/garyyu/rust-secp256k1-zkp/wiki) documents and a lot of demos.

`secp256k1` is an actively maintained optimized C library for EC(Elliptic Curve) operations on curve secp256k1, the [main contributors](https://github.com/bitcoin/secp256k1/graphs/contributors) include:
* [Peter Wuille](https://www.linkedin.com/in/pieterwuille), Co-founder and Core Tech Engineer of Blockstream. 
* [Gregory Maxwell](https://github.com/gmaxwell), Bitcoin Core developer, Co-Founder and CTO of Blockstream ([resigned](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-January/015586.html) from Blockstream 2017 Nov.).
* [Andrew Poelstra](https://www.linkedin.com/in/andrew-poelstra-958a75106/), Mathematician at Blockstream.
* And all other around fifty contributors.

You can find more detail about it on [https://github.com/bitcoin/secp256k1](https://github.com/bitcoin/secp256k1).


This Rust library:
* exposes type-safe Rust bindings for all `libsecp256k1` functions
* implements key generation
* implements deterministic nonce generation via RFC6979
* implements many unit tests, adding to those already present in `libsecp256k1`
* makes no allocations (except in unit tests) for efficiency and use in freestanding implementations
* including: schnorr signature, pedersen commitment, bulletproof

### Build and Run

```
git clone --recursive https://github.com/garyyu/rust-secp256k1-zkp.git
cd rust-secp256k1-zkp
cargo build --release
cargo test --release -- demo_ecdsa_sign --nocapture
```
replace `demo_ecdsa_sign` with any demo/test as you want.

### Documents
* [Rustdoc of crate secp256k1](https://www.wpsoftware.net/rustdoc/secp256k1/)
* [Wiki of this library](https://github.com/garyyu/rust-secp256k1-zkp/wiki)

If you find this repo or the Wiki documents are useful for you, please **star** it (click that Star button on top right corner), and then find it later from **_Your stars_** menu on your github account.

And welcome to edit the Wiki pages and/or fork this repo, to contribute for the open source.

