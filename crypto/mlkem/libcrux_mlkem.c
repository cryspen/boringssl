#include <string.h>

#include "../internal.h"
#include "libcrux_mlkem.h"

#include <openssl/bytestring.h>
#include <openssl/mlkem.h>
#include <openssl/rand.h>

#include "../../third_party/libcrux/libcrux_mlkem768_portable.h"

#if defined(OPENSSL_X86_64)
#include "../../third_party/libcrux/libcrux_mlkem768_avx2.h"
#endif

void MLKEM768_generate_key_external_seed_libcrux(
    uint8_t out_encoded_public_key[MLKEM768_PUBLIC_KEY_BYTES],
    struct MLKEM768_private_key *out_private_key,
    const uint8_t seed[MLKEM_SEED_BYTES]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    static_assert(sizeof(struct MLKEM768_private_key) == sizeof(libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked), "");
    // static_assert(alignof(struct MLKEM768_private_key) % alignof(libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked) == 0, ""); // fails
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked t;
    libcrux_ml_kem_mlkem768_avx2_unpacked_generate_key_pair_mut((/*nonconst*/uint8_t*)seed, &t);
    OPENSSL_memcpy(out_private_key, &t, sizeof(struct MLKEM768_private_key));
  } else
#endif  // OPENSSL_X86_64
  {
    static_assert(sizeof(struct MLKEM768_private_key) == sizeof(libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked), "");
    static_assert(alignof(struct MLKEM768_private_key) % alignof(libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked) == 0, "");
    libcrux_ml_kem_mlkem768_portable_unpacked_generate_key_pair_mut((/*nonconst*/uint8_t*)seed, (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked*)out_private_key);
  }

  struct MLKEM768_public_key public_key;
  MLKEM768_public_from_private(&public_key, out_private_key);
  static_assert(sizeof(struct MLKEM768_public_key) == sizeof(libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_63), "");
  // static_assert(alignof(struct MLKEM768_public_key) % alignof(libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_63) == 0, "");
  static_assert(MLKEM768_PUBLIC_KEY_BYTES == sizeof(libcrux_ml_kem_types_MlKemPublicKey_30), "");
  static_assert(alignof(uint8_t) % alignof(libcrux_ml_kem_types_MlKemPublicKey_30) == 0, "");
  libcrux_ml_kem_mlkem768_portable_unpacked_serialized_public_key((libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_a0*)&public_key, (libcrux_ml_kem_types_MlKemPublicKey_30*)out_encoded_public_key);
}

int MLKEM768_private_key_from_seed_libcrux(
    struct MLKEM768_private_key *out_private_key, const uint8_t *seed,
    size_t seed_len) {
  if (seed_len != MLKEM_SEED_BYTES) {
    return 0;
  }
  uint8_t public_key_bytes[MLKEM768_PUBLIC_KEY_BYTES];
  MLKEM768_generate_key_external_seed(public_key_bytes, out_private_key, seed);
  return 1;
}

void MLKEM768_public_from_private_libcrux(struct MLKEM768_public_key *out_public_key,
                        const struct MLKEM768_private_key *key_pair) {
  static_assert(sizeof(struct MLKEM768_private_key) == sizeof(libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked), "");
  static_assert(alignof(struct MLKEM768_private_key) % alignof(libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked) == 0, "");
  static_assert(sizeof(struct MLKEM768_public_key) == sizeof(libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_63), "");
  // static_assert(alignof(struct MLKEM768_public_key) % alignof(libcrux_ml_kem_ind_cca_unpacked_MlKemPublicKeyUnpacked_63) == 0, "");
  libcrux_ml_kem_mlkem768_portable_unpacked_public_key(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *)
          key_pair,
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked *)
          out_public_key);
}

// Calls |MLKEM768_encap_external_entropy| with random bytes from |RAND_bytes|
void MLKEM768_encap_libcrux(uint8_t out_ciphertext[MLKEM768_CIPHERTEXT_BYTES],
                    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
                    const struct MLKEM768_public_key *public_key) {
  uint8_t entropy[MLKEM_ENCAP_ENTROPY];
  RAND_bytes(entropy, MLKEM_ENCAP_ENTROPY);
  MLKEM768_encap_external_entropy(out_ciphertext, out_shared_secret, public_key,
                                  entropy);
}

int MLKEM768_parse_public_key_libcrux(struct MLKEM768_public_key *out_public_key,
                            CBS *in) {
  libcrux_ml_kem_types_MlKemPublicKey_30 public_key;
  if (!CBS_copy_bytes(in, (uint8_t *)&public_key.value,
                      MLKEM768_PUBLIC_KEY_BYTES)) {
    // Couldn't read the necessary bytes.
    printf("Error reading bytes from CBS\n");
    return 0;
  }

  // Validate the public key
  if (!libcrux_ml_kem_mlkem768_portable_validate_public_key(&public_key)) {
    // The public key is invalid.
    printf("Invalid public key\n");
    return 0;
  }


#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    // Unpack the public key
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked key;
    libcrux_ml_kem_mlkem768_avx2_unpacked_unpacked_public_key(&public_key,
                                                              &key);

    // Copy m256i from key.
    OPENSSL_memcpy(&out_public_key->opaque.bytes, &key, sizeof(out_public_key->opaque.bytes));

    // Write out public key to bytes

    return 1;
  }
#endif  // OPENSSL_X86_64

  // Unpack the public key
  libcrux_ml_kem_mlkem768_portable_unpacked_unpacked_public_key(
      &public_key,
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked *)
          out_public_key);

  return 1;
}

int MLKEM768_marshal_public_key_libcrux(
    CBB *out, const struct MLKEM768_public_key *public_key) {
  libcrux_ml_kem_types_MlKemPublicKey_30 serialized;
  libcrux_ml_kem_mlkem768_portable_unpacked_serialized_public_key(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked *)
          public_key,
      &serialized);

  if (!CBB_add_bytes(out, serialized.value, sizeof(serialized.value))) {
    return 0;
  }

  return 1;
}

void MLKEM768_encap_external_entropy_libcrux(
    uint8_t out_ciphertext[MLKEM768_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const struct MLKEM768_public_key *public_key,
    const uint8_t entropy[32]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    // Copy m256i from key.
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked key;
    OPENSSL_memcpy(&key, &public_key->opaque.bytes, sizeof(public_key->opaque.bytes));


    tuple_c2 ct_zz = libcrux_ml_kem_mlkem768_avx2_unpacked_encapsulate(
        &key, (uint8_t *)&entropy[0]);

    OPENSSL_memcpy(out_ciphertext, ct_zz.fst.value, MLKEM768_CIPHERTEXT_BYTES);
    OPENSSL_memcpy(out_shared_secret, ct_zz.snd, MLKEM_SHARED_SECRET_BYTES);

    return;
  }
#endif  // OPENSSL_X86_64

  tuple_c2 ct_zz = libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked *)
          public_key,
      (uint8_t *)&entropy[0]);

  OPENSSL_memcpy(out_ciphertext, ct_zz.fst.value, MLKEM768_CIPHERTEXT_BYTES);
  OPENSSL_memcpy(out_shared_secret, ct_zz.snd, MLKEM_SHARED_SECRET_BYTES);
}

int MLKEM768_decap_libcrux(uint8_t out_ss[MLKEM_SHARED_SECRET_BYTES],
			 const uint8_t *ct, size_t ciphertext_len,
			 const struct MLKEM768_private_key *private_key) {
  if (ciphertext_len != MLKEM768_CIPHERTEXT_BYTES) {
    return 0;
  }
  static_assert(MLKEM768_CIPHERTEXT_BYTES == sizeof(libcrux_ml_kem_mlkem768_MlKem768Ciphertext), "");
  static_assert(1 == alignof(libcrux_ml_kem_mlkem768_MlKem768Ciphertext), "");

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {

    static_assert(sizeof(struct MLKEM768_private_key) == sizeof(libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked), "");
    // static_assert(alignof(struct MLKEM768_private_key) % alignof(libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked) == 0, ""); // fails
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked t;
    OPENSSL_memcpy(&t, private_key, sizeof(t));
    libcrux_ml_kem_mlkem768_avx2_unpacked_decapsulate(&t, (libcrux_ml_kem_mlkem768_MlKem768Ciphertext*)ct, out_ss);
    return 1;
  }
#endif  // OPENSSL_X86_64
  static_assert(sizeof(struct MLKEM768_private_key) == sizeof(libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked), "");
  static_assert(alignof(struct MLKEM768_private_key) % alignof(libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked) == 0, "");
  libcrux_ml_kem_ind_cca_unpacked_decapsulate_51((libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked*)private_key, (libcrux_ml_kem_mlkem768_MlKem768Ciphertext*)ct, out_ss);
  return 1;
}

void MLKEM768_generate_key_libcrux(uint8_t out_encoded_public_key[MLKEM768_PUBLIC_KEY_BYTES],
                           uint8_t optional_out_seed[MLKEM_SEED_BYTES],
                           struct MLKEM768_private_key *out_private_key) {
  uint8_t seed[MLKEM_SEED_BYTES];
  RAND_bytes(seed, sizeof(seed));
  if (optional_out_seed) {
    OPENSSL_memcpy(optional_out_seed, seed, sizeof(seed));
  }
  MLKEM768_generate_key_external_seed(out_encoded_public_key, out_private_key,
                                      seed);
}

int MLKEM768_marshal_private_key_libcrux(
    CBB *out, const struct MLKEM768_private_key *private_key) {
      libcrux_ml_kem_types_MlKemPrivateKey_d9 serialized;

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    libcrux_ml_kem_mlkem768_avx2_unpacked_key_pair_serialized_private_key_mut(
        (libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked *)
            private_key,
        &serialized);
  } else 
#endif
 {
  libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_serialized_private_key_mut(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *)
          private_key,
      &serialized);
 }

  if (!CBB_add_bytes(out, serialized.value, sizeof(serialized.value))) {
    return 0;
  }
  return 1;
}

int MLKEM768_parse_private_key_libcrux(
    struct MLKEM768_private_key *out_private_key, CBS *in) {
 
  libcrux_ml_kem_types_MlKemPrivateKey_d9 private_key_in;
  if (!CBS_copy_bytes(in, (uint8_t *)&private_key_in.value,
                      MLKEM768_PRIVATE_KEY_BYTES)) {
    // Couldn't read the necessary bytes.
    printf("Error reading bytes from CBS\n");
    return 0;
  }

  // Validate the private key
  if (!libcrux_ml_kem_mlkem768_portable_validate_private_key_only(&private_key_in)) {
    return 0;
  }

  libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_from_private_mut(
    &private_key_in,
    (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked*)out_private_key);

  return 1; // TODO
}
