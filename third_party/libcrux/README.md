# Libcrux Cryptography

The files in this directory are generated using hax and eurydice from the libcrux
library. They are written natively in Rust and exported to C with hax and eurydice.
All files are included under the Apache2.0 license. (See LICENSE file.)

Necessary hand-written glue-code is in

- `include/eurydice_glue.h`
- `include/intrinsics/libcrux_mlkem_avx2.h`

The high level APIs in `api` are hand-written as well.

The Libcrux SHA3 code that is used in the ML-KEM implementation is provided as well.
Note that this code is not verified.
But it provides APIs that are specific to ML-KEM.

All the code relies on the Karamel glue code from https://github.com/FStarLang/karamel,
which is provided in `./karamel`.

A standalone cmake file is provided for convenience to build only this code.

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -G"Ninja" ..
cmake --build build
```
