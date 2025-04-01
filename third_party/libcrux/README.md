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


