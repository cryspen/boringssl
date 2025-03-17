// Copyright 2025 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/mlkem.h>
#include <openssl/rand.h>

#include "../bcm_interface.h"

#include "../../../third_party/libcrux/libcrux_mlkem768_portable.h"

#if defined(OPENSSL_X86_64)
#include "../../../third_party/libcrux/libcrux_mlkem768_avx2.h"
#endif

// static void MLKEM768_public_from_private_libcrux(
//     struct MLKEM768_public_key *out_public_key,
//     const struct MLKEM768_private_key *key_pair) {
//   {
//     static_assert(
//         sizeof(struct MLKEM768_private_key) ==
//             sizeof(
//                 libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked),
//         "");
//     static_assert(
//         alignof(struct MLKEM768_private_key) %
//                 alignof(
//                     libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked) ==
//             0,
//         "");
//     static_assert(
//         sizeof(struct MLKEM768_public_key) ==
//             sizeof(
//                 libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked),
//         "");
//     static_assert(
//         alignof(struct MLKEM768_public_key) %
//                 alignof(
//                     libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked) ==
//             0,
//         "");
//   }

//   printf("key_pair\n");
//   for (size_t i = 0; i < sizeof(struct MLKEM768_private_key); i++) {
//     printf("%02x", key_pair->opaque.bytes[i]);
//   }
//   printf("\n");

//   libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked
//       libcrux_key_pair;
//   OPENSSL_memcpy(&libcrux_key_pair, key_pair->opaque.bytes,
//                  sizeof(struct MLKEM768_private_key));
//   libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked
//       libcrux_public_key;

//   libcrux_ml_kem_mlkem768_avx2_unpacked_public_key(&libcrux_key_pair,
//                                                    &libcrux_public_key);

//   OPENSSL_memcpy(out_public_key, &libcrux_public_key,
//                  sizeof(struct MLKEM768_public_key));
// }

// static void MLKEM768_generate_key_external_seed_libcrux(
//     uint8_t out_encoded_public_key[MLKEM768_PUBLIC_KEY_BYTES],
//     struct MLKEM768_private_key *out_private_key,
//     const uint8_t seed[MLKEM_SEED_BYTES]) {
//   static_assert(MLKEM768_PUBLIC_KEY_BYTES ==
//                     sizeof(libcrux_ml_kem_types_MlKemPublicKey_30),
//                 "");

//   // We have to put values on the heap here to avoid exceeding the stack
//   frame
//   // size limit.

// #if defined(OPENSSL_X86_64)
//   if (CRYPTO_is_AVX2_capable()) {
//     static_assert(
//         sizeof(struct MLKEM768_private_key) ==
//             sizeof(
//                 libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked),
//         "");

//     std::unique_ptr<
//         libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked>
//         libcrux_key_pair(
//             new
//             libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked);
//     libcrux_ml_kem_mlkem768_avx2_unpacked_generate_key_pair_mut(
//         const_cast<uint8_t *>(seed), libcrux_key_pair.get());
//     OPENSSL_memcpy(out_private_key, libcrux_key_pair.get(),
//                    sizeof(struct MLKEM768_private_key));

//     std::unique_ptr<libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_63>
//         unpacked_public_key(
//             new libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_63);
//     libcrux_ml_kem_mlkem768_avx2_unpacked_public_key(libcrux_key_pair.get(),
//                                                      unpacked_public_key.get());


//     std::unique_ptr<libcrux_ml_kem_types_MlKemPublicKey_30>
//     libcrux_public_key(
//         new libcrux_ml_kem_types_MlKemPublicKey_30);
//     libcrux_ml_kem_mlkem768_avx2_unpacked_serialized_public_key(
//         unpacked_public_key.get(), libcrux_public_key.get());

//     OPENSSL_memcpy(out_encoded_public_key, libcrux_public_key->value,
//                    sizeof(libcrux_ml_kem_types_MlKemPublicKey_30));

//     return;
//   }
// #endif  // OPENSSL_X86_64
//   static_assert(
//       sizeof(struct MLKEM768_private_key) ==
//           sizeof(
//               libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked),
//       "");
//   static_assert(
//       alignof(struct MLKEM768_private_key) %
//               alignof(
//                   libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked)
//                   ==
//           0,
//       "");
//   static_assert(
//       sizeof(struct MLKEM768_public_key) ==
//           sizeof(libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0),
//       "");
//   static_assert(
//       alignof(struct MLKEM768_public_key) %
//               alignof(
//                   libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0)
//                   ==
//           0,
//       "");
//   static_assert(MLKEM768_PUBLIC_KEY_BYTES ==
//                     sizeof(libcrux_ml_kem_types_MlKemPublicKey_30),
//                 "");
//   static_assert(
//       alignof(uint8_t) % alignof(libcrux_ml_kem_types_MlKemPublicKey_30) ==
//       0,
//       "");

//   std::unique_ptr<
//       libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked>
//       libcrux_key_pair(
//           new
//           libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked);

//   libcrux_ml_kem_mlkem768_portable_unpacked_generate_key_pair_mut(
//       const_cast<uint8_t *>(seed), libcrux_key_pair.get());

//   OPENSSL_memcpy(out_private_key, libcrux_key_pair.get(),
//                  sizeof(struct MLKEM768_private_key));

//   std::unique_ptr<
//       libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked>
//       public_key(
//           new
//           libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked);
//   libcrux_ml_kem_mlkem768_portable_unpacked_public_key(libcrux_key_pair.get(),
//                                                        public_key.get());


//   std::unique_ptr<libcrux_ml_kem_types_MlKemPublicKey_30> libcrux_public_key(
//       new libcrux_ml_kem_types_MlKemPublicKey_30);
//   libcrux_ml_kem_mlkem768_portable_unpacked_serialized_public_key(
//       public_key.get(), libcrux_public_key.get());

//   OPENSSL_memcpy(out_encoded_public_key, libcrux_public_key->value,
//                  sizeof(libcrux_ml_kem_types_MlKemPublicKey_30));
// }

// static int MLKEM768_private_key_from_seed_libcrux(
//     struct MLKEM768_private_key *out_private_key, const uint8_t *seed,
//     size_t seed_len) {
//   if (seed_len != MLKEM_SEED_BYTES) {
//     return 0;
//   }
//   uint8_t public_key_bytes[MLKEM768_PUBLIC_KEY_BYTES];
//   MLKEM768_generate_key_external_seed_libcrux(public_key_bytes,
//   out_private_key,
//                                               seed);
//   return 1;
// }

// static int MLKEM768_parse_public_key_libcrux(
//     struct MLKEM768_public_key *out_public_key, CBS *in) {
//   libcrux_ml_kem_types_MlKemPublicKey_30 public_key;
//   if (!CBS_copy_bytes(in, (uint8_t *)&public_key.value,
//                       MLKEM768_PUBLIC_KEY_BYTES) ||
//       CBS_len(in) != 0) {
//     // Couldn't read the necessary bytes.
//     return 0;
//   }

//   // Validate the public key.
//   if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&public_key)) {
//     // The public key is invalid.
//     return 0;
//   }


// #if defined(OPENSSL_X86_64)
//   if (CRYPTO_is_AVX2_capable()) {
//     static_assert(
//         sizeof(struct MLKEM768_public_key) ==
//             sizeof(
//                 libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked),
//         "");

//     // Unpack the public key
//     libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked key;
//     libcrux_ml_kem_mlkem768_avx2_unpacked_unpacked_public_key(&public_key,
//                                                               &key);

//     // Write out public key to bytes
//     // Copy m256i from key.
//     OPENSSL_memcpy(&out_public_key->opaque.bytes, &key,
//                    sizeof(out_public_key->opaque.bytes));

//     return 1;
//   }
// #endif  // OPENSSL_X86_64
//   static_assert(
//       sizeof(struct MLKEM768_public_key) ==
//           sizeof(
//               libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked),
//       "");

//   libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked key;

//   // Unpack the public key
//   libcrux_ml_kem_mlkem768_portable_unpacked_unpacked_public_key(&public_key,
//                                                                 &key);

//   OPENSSL_memcpy(&out_public_key->opaque.bytes, &key,
//                  sizeof(out_public_key->opaque.bytes));

//   return 1;
// }

// static int MLKEM768_marshal_public_key_libcrux(
//     CBB *out, const struct MLKEM768_public_key *public_key) {
//   static_assert(
//       sizeof(struct MLKEM768_public_key) ==
//           sizeof(
//               libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked),
//       "");

//   libcrux_ml_kem_types_MlKemPublicKey_30 serialized;
//   libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked
//       libcrux_public_key;
//   OPENSSL_memcpy(&libcrux_public_key, public_key,
//                  sizeof(struct MLKEM768_public_key));

//   libcrux_ml_kem_mlkem768_portable_unpacked_serialized_public_key(
//       &libcrux_public_key, &serialized);

//   if (!CBB_add_bytes(out, serialized.value, sizeof(serialized.value))) {
//     return 0;
//   }

//   return 1;
// }

// static void MLKEM768_encap_external_entropy_libcrux(
//     uint8_t out_ciphertext[MLKEM768_CIPHERTEXT_BYTES],
//     uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
//     const struct MLKEM768_public_key *public_key, const uint8_t entropy[32])
//     {
// #if defined(OPENSSL_X86_64)
//   if (CRYPTO_is_AVX2_capable()) {
//     static_assert(
//         sizeof(struct MLKEM768_public_key) ==
//             sizeof(
//                 libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked),
//         "");

//     // Copy m256i from key.
//     libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked key;
//     OPENSSL_memcpy(&key, &public_key->opaque.bytes,
//                    sizeof(public_key->opaque.bytes));

//     tuple_c2 ct_zz = libcrux_ml_kem_mlkem768_avx2_unpacked_encapsulate(
//         &key, const_cast<uint8_t *>(entropy));

//     OPENSSL_memcpy(out_ciphertext, ct_zz.fst.value,
//     MLKEM768_CIPHERTEXT_BYTES); OPENSSL_memcpy(out_shared_secret, ct_zz.snd,
//     MLKEM_SHARED_SECRET_BYTES);

//     return;
//   }
// #endif  // OPENSSL_X86_64
//   static_assert(
//       sizeof(struct MLKEM768_public_key) ==
//           sizeof(
//               libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked),
//       "");

//   libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked key;
//   OPENSSL_memcpy(&key, &public_key->opaque.bytes,
//                  sizeof(public_key->opaque.bytes));

//   tuple_c2 ct_zz = libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
//       &key, const_cast<uint8_t *>(entropy));

//   OPENSSL_memcpy(out_ciphertext, ct_zz.fst.value, MLKEM768_CIPHERTEXT_BYTES);
//   OPENSSL_memcpy(out_shared_secret, ct_zz.snd, MLKEM_SHARED_SECRET_BYTES);
// }

// static int MLKEM768_decap_libcrux(
//     uint8_t out_ss[MLKEM_SHARED_SECRET_BYTES], const uint8_t *ct,
//     size_t ciphertext_len, const struct MLKEM768_private_key *private_key) {
//   if (ciphertext_len != MLKEM768_CIPHERTEXT_BYTES) {
//     return 0;
//   }
//   static_assert(MLKEM768_CIPHERTEXT_BYTES ==
//                     sizeof(libcrux_ml_kem_mlkem768_MlKem768Ciphertext),
//                 "");
//   static_assert(1 == alignof(libcrux_ml_kem_mlkem768_MlKem768Ciphertext),
//   "");

// #if defined(OPENSSL_X86_64)
//   if (CRYPTO_is_AVX2_capable()) {
//     static_assert(
//         sizeof(struct MLKEM768_private_key) ==
//             sizeof(
//                 libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked),
//         "");

//     libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked
//     libcrux_key; OPENSSL_memcpy(&libcrux_key, private_key,
//                    sizeof(struct MLKEM768_private_key));

//     libcrux_ml_kem_mlkem768_avx2_unpacked_decapsulate(
//         &libcrux_key, (libcrux_ml_kem_mlkem768_MlKem768Ciphertext *)ct,
//         out_ss);

//     return 1;
//   }
// #endif  // OPENSSL_X86_64
//   static_assert(
//       sizeof(struct MLKEM768_private_key) ==
//           sizeof(
//               libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked),
//       "");
//   static_assert(
//       alignof(struct MLKEM768_private_key) %
//               alignof(
//                   libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked)
//                   ==
//           0,
//       "");


//   libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked
//   libcrux_key; OPENSSL_memcpy(&libcrux_key, private_key,
//                  sizeof(struct MLKEM768_private_key));

//   libcrux_ml_kem_mlkem768_MlKem768Ciphertext libcrux_ct;
//   OPENSSL_memcpy(&libcrux_ct, ct,
//                  sizeof(libcrux_ml_kem_mlkem768_MlKem768Ciphertext));

//   libcrux_ml_kem_ind_cca_unpacked_decapsulate_51(&libcrux_key, &libcrux_ct,
//                                                  out_ss);

//   return 1;
// }

// static int MLKEM768_marshal_private_key_libcrux(
//     CBB *out, const struct MLKEM768_private_key *private_key) {
//   libcrux_ml_kem_types_MlKemPrivateKey_d9 serialized;

// #if defined(OPENSSL_X86_64)
//   if (CRYPTO_is_AVX2_capable()) {
//     static_assert(
//         sizeof(struct MLKEM768_private_key) ==
//             sizeof(
//                 libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked),
//         "");

//     libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked libcrux_key;
//     OPENSSL_memcpy(
//         &libcrux_key, private_key,
//         sizeof(libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked));

//     libcrux_ml_kem_mlkem768_avx2_unpacked_key_pair_serialized_private_key_mut(
//         &libcrux_key, &serialized);
//   } else
// #endif
//   {
//     static_assert(
//         sizeof(struct MLKEM768_private_key) ==
//             sizeof(
//                 libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked),
//         "");

//     libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked
//         libcrux_key;
//     OPENSSL_memcpy(
//         &libcrux_key, private_key,
//         sizeof(
//             libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked));

//     libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_serialized_private_key_mut(
//         &libcrux_key, &serialized);
//   }

//   if (!CBB_add_bytes(out, serialized.value, sizeof(serialized.value))) {
//     return 0;
//   }
//   return 1;
// }

// static int MLKEM768_parse_private_key_libcrux(
//     struct MLKEM768_private_key *out_private_key, CBS *in) {
//   libcrux_ml_kem_types_MlKemPrivateKey_d9 private_key_in;
//   if (!CBS_copy_bytes(in, (uint8_t *)&private_key_in.value,
//                       BCM_MLKEM768_PRIVATE_KEY_BYTES) ||
//       CBS_len(in) != 0) {
//     // Couldn't read the necessary bytes.
//     return 0;
//   }

//   // Validate the private key
//   if (!libcrux_ml_kem_mlkem768_portable_validate_private_key_only(
//           &private_key_in)) {
//     return 0;
//   }

//   libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked key;
//   libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_from_private_mut(
//       &private_key_in, &key);

//   OPENSSL_memcpy(
//       out_private_key, &key,
//       sizeof(
//           libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked));

//   // Check that the private key values are in the correct domain.
//   // This is not a check from the spec, so we do it here on top.
//   bool ok = true;
//   for (size_t i = 0; i < 3; i++) {
//     for (size_t j = 0; j < 16; j++) {
//       for (size_t k = 0; k < 16; k++) {
//         ok &= key.private_key.ind_cpa_private_key.secret_as_ntt[i]
//                   .coefficients[j]
//                   .elements[k] <= 3329;
//       }
//     }
//   }
//   if (constant_time_declassify_int(!ok)) {
//     return 0;
//   }

//   return 1;
// }

// // Calls |MLKEM768_encap_external_entropy| with random bytes from
// |RAND_bytes| static void MLKEM768_encap_libcrux(
//     uint8_t out_ciphertext[MLKEM768_CIPHERTEXT_BYTES],
//     uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
//     const struct MLKEM768_public_key *public_key) {
//   uint8_t entropy[BCM_MLKEM_ENCAP_ENTROPY];
//   RAND_bytes(entropy, BCM_MLKEM_ENCAP_ENTROPY);
//   MLKEM768_encap_external_entropy_libcrux(out_ciphertext, out_shared_secret,
//                                           public_key, entropy);
// }
