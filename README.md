# iden3comm

Golang implementation of iden3comm protocol

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as below, without any additional terms or conditions.

## Build constraints

### prover_disabled

The `prover_disabled` build tag prevents the dependency on the `librapidsnark.a` library.

**Behavior with `prover_disabled` flag:**
- ZK proof verification remains fully functional
- ZK proof generation will fail with an error when calling the `Pack` method from `ZKPPacker`

To enable both ZK proof generation and verification, build the library without the `prover_disabled` flag.

## License

&copy; 2023 0kims Association

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.
