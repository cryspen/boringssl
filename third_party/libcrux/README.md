# Libcrux Cryptography

The files in this directory are generated using hax and eurydice from the libcrux
library. They are written natively in Rust and exported to C with hax and eurydice.
All files are included under the Apache2.0 license. (See LICENSE file.)

Necessary hand-written glue-code is in:

- `eurydice_glue.h`
- `intrinsics/libcrux_intrinsics_avx2.h`
- `karamel/target.h`

The verified ML-KEM code (generated from Rust) is in:
- `libcrux_mlkem768_portable.h`: portable implementation of ML-KEM 768
- `libcrux_mlkem768_avx2.h`: AVX2 implementation of ML-KEM 768
- `libcrux_ct_ops.h`: constant-time operations used in our code
- `libcrux_mlkem_core.h`: Types and functions used by both portable and AVX2 implementations

The Libcrux SHA3 code that is used in the ML-KEM implementation is provided as well:
- `libcrux_sha3_portable.h`: A portable implementation of SHA-3 (including a KeccakX4 API)
- `libcrux_sha3_avx2.h`: An AVX2 implementation of SHA-3 (including KeccakX4)
Note that this code is not verified, but it provides APIs that are needed by ML-KEM.

Please see [the libcrux repository](https://github.com/cryspen/libcrux/blob/main/libcrux-ml-kem/TOOLS.md)
for details on how to re-generate this code.

## Notes
* We cood look into adding 1024 as well to also improve the integration in `mlkem.cc.inc`. The code exists in libcrux.
* Functions in `libcrux_ct_ops.h` could be replaced with BoringSSL functions, or we could introduce guards in order to improve ct guarantees.
* We could look into adding neon optimized versions. They exist in libcrux.

## Benchmarks (August 2025)

### This code

- Linux i7-8700
    - avx2
        - generate + decap: 31618.8 ops/sec
        - parse + encap: 50610.0 ops/sec
    - portable
        - generate + decap: 14337.2 ops/sec
        - parse + encap: 23116.2 ops/sec
- macOS M1 Pro (portable)
    - generate + decap: 29922.3 ops/sec
    - parse + encap: 50722.5 ops/sec

### BoringSSL main

- Linux i7-8700
    - generate + decap: 10969.0 ops/sec
    - parse + encap: 20174.2 ops/sec
- macOS M1 Pro
    - generate + decap: 20996.3 ops/sec
    - parse + encap: 39950.3 ops/sec
