#include <string.h>

#include "../internal.h"

#include <openssl/bytestring.h>
#include <openssl/libcrux-mlkem.h>
#include <openssl/rand.h>

#include "../../third_party/libcrux/libcrux_mlkem768_portable.h"
#include "../../third_party/libcrux/libcrux_mlkem768_portable_types.h"

#if defined(OPENSSL_X86_64)
#include "../../third_party/libcrux/libcrux_mlkem768_avx2.h"
#include "../../third_party/libcrux/libcrux_mlkem768_avx2_types.h"
#endif

void Mlkem768_GenerateKeyPair(
    uint8_t *out_pk, uint8_t *out_sk,
    const uint8_t randomness[MLKEM768_KEY_GENERATION_RANDOMNESS]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    libcrux_ml_kem_mlkem768_MlKem768KeyPair result =
        libcrux_ml_kem_mlkem768_avx2_generate_key_pair((uint8_t *)randomness);
    memcpy(out_pk, result.pk.value, MLKEM768_PUBLICKEYBYTES);
    memcpy(out_sk, result.sk.value, MLKEM768_SECRETKEYBYTES);

    return;
  }
#endif  // OPENSSL_X86_64

  libcrux_ml_kem_mlkem768_MlKem768KeyPair result =
      libcrux_ml_kem_mlkem768_portable_generate_key_pair((uint8_t *)randomness);

  memcpy(out_pk, result.pk.value, MLKEM768_PUBLICKEYBYTES);
  memcpy(out_sk, result.sk.value, MLKEM768_SECRETKEYBYTES);
}

void Mlkem768_GenerateKeyPairUnpacked(
    uint8_t out_encoded_public_key[MLKEM768_PUBLICKEYBYTES],
    uint8_t optional_out_seed[MLKEM768_KEY_GENERATION_RANDOMNESS],
    struct MlKem768_KeyPairUnpacked *out_key_pair) {
  uint8_t seed[MLKEM768_KEY_GENERATION_RANDOMNESS];
  RAND_bytes(seed, sizeof(seed));
  if (optional_out_seed) {
    OPENSSL_memcpy(optional_out_seed, seed, sizeof(seed));
  }

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked keys;
    libcrux_ml_kem_mlkem768_avx2_unpacked_generate_key_pair(seed, &keys);

    // Copy m256i into keys.
    Eurydice_slice key_slice = EURYDICE_SLICE(
        out_key_pair->opaque.bytes, 0, sizeof(out_key_pair->opaque.bytes));
    libcrux_ml_kem_mlkem768_avx2_unpacked_key_pair_to_bytes(&keys, key_slice);

    libcrux_ml_kem_types_MlKemPublicKey_15 pk = {0};
    libcrux_ml_kem_mlkem768_avx2_unpacked_key_pair_serialized_public_key(
        (libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked *)
            out_key_pair,
        &pk);
    OPENSSL_memcpy(out_encoded_public_key, pk.value, MLKEM768_PUBLICKEYBYTES);

    return;
  }
#endif  // OPENSSL_X86_64

  libcrux_ml_kem_mlkem768_portable_unpacked_generate_key_pair(
      seed,
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *)
          out_key_pair);

  libcrux_ml_kem_types_MlKemPublicKey_15 pk = {0};
  libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_serialized_public_key(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *)
          out_key_pair,
      &pk);
  OPENSSL_memcpy(out_encoded_public_key, pk.value, MLKEM768_PUBLICKEYBYTES);
}

int Mlkem768_GenerateKeyPairUnpacked_FromSeed(
    struct MlKem768_KeyPairUnpacked *out_key_pair, const uint8_t *seed,
    size_t seed_len) {
  if (seed_len != MLKEM768_KEY_GENERATION_RANDOMNESS) {
    return 0;
  }


#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked keys;
    libcrux_ml_kem_mlkem768_avx2_unpacked_generate_key_pair((uint8_t *)seed,
                                                            &keys);

    // Copy m256i into keys.
    Eurydice_slice key_slice = EURYDICE_SLICE(
        out_key_pair->opaque.bytes, 0, sizeof(out_key_pair->opaque.bytes));
    libcrux_ml_kem_mlkem768_avx2_unpacked_key_pair_to_bytes(&keys, key_slice);

    libcrux_ml_kem_types_MlKemPublicKey_15 pk = {0};
    libcrux_ml_kem_mlkem768_avx2_unpacked_key_pair_serialized_public_key(
        (libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked *)
            out_key_pair,
        &pk);
    return 1;
  }
#endif  // OPENSSL_X86_64

  libcrux_ml_kem_mlkem768_portable_unpacked_generate_key_pair(
      (uint8_t *)seed,
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *)
          out_key_pair);

  libcrux_ml_kem_types_MlKemPublicKey_15 pk = {0};
  libcrux_ml_kem_mlkem768_portable_unpacked_key_pair_serialized_public_key(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *)
          out_key_pair,
      &pk);

  return 1;
}

void MlKem768_PublicKey(struct MlKem768_PublicKeyUnpacked *out_public_key,
                        const struct MlKem768_KeyPairUnpacked *key_pair) {
  libcrux_ml_kem_mlkem768_portable_unpacked_public_key(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *)
          key_pair,
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked *)
          out_public_key);
}

int Mlkem768_Encapsulate(uint8_t *out_ct, uint8_t *out_ss,
                         const uint8_t (*pk)[MLKEM768_PUBLICKEYBYTES],
                         const uint8_t randomness[MLKEM768_ENCAPS_RANDOMNESS]) {
  libcrux_ml_kem_types_MlKemPublicKey_15 public_key;
  memcpy(public_key.value, pk, MLKEM768_PUBLICKEYBYTES);


  bool valid_pk =
      libcrux_ml_kem_mlkem768_portable_validate_public_key(&public_key);
  if (!valid_pk) {
    // The public key is invalid, abort.
    return 0;
  }

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    tuple_3c result = libcrux_ml_kem_mlkem768_avx2_encapsulate(
        &public_key, (uint8_t *)randomness);

    memcpy(out_ct, result.fst.value, MLKEM768_CIPHERTEXTBYTES);
    memcpy(out_ss, result.snd, MLKEM768_SHAREDSECRETBYTES);

    return 1;
  }
#endif  // OPENSSL_X86_64

  tuple_3c result = libcrux_ml_kem_mlkem768_portable_encapsulate(
      &public_key, (uint8_t *)randomness);

  memcpy(out_ct, result.fst.value, MLKEM768_CIPHERTEXTBYTES);
  memcpy(out_ss, result.snd, MLKEM768_SHAREDSECRETBYTES);

  return 1;
}

int Mlkem768_ParsePublicKey(struct MlKem768_PublicKeyUnpacked *out_public_key,
                            CBS *in) {
  libcrux_ml_kem_types_MlKemPublicKey_15 public_key;
  if (!CBS_copy_bytes(in, (uint8_t *)&public_key.value,
                      MLKEM768_PUBLICKEYBYTES)) {
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
    Eurydice_slice key_slice = EURYDICE_SLICE(
        out_public_key->opaque.bytes, 0, sizeof(out_public_key->opaque.bytes));
    libcrux_ml_kem_mlkem768_avx2_unpacked_public_key_to_bytes(&key, key_slice);

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

int Mlkem768_MarshalPublicKey(
    CBB *out, const struct MlKem768_PublicKeyUnpacked *public_key) {
  libcrux_ml_kem_types_MlKemPublicKey_15 serialized;
  libcrux_ml_kem_mlkem768_portable_unpacked_serialized_public_key(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked *)
          public_key,
      &serialized);

  if (!CBB_add_bytes(out, serialized.value, sizeof(serialized.value))) {
    return 0;
  }

  return 1;
}

void MlKem768_Encapsulate(uint8_t out_ciphertext[MLKEM768_CIPHERTEXTBYTES],
                          uint8_t out_shared_secret[MLKEM768_SHAREDSECRETBYTES],
                          const struct MlKem768_PublicKeyUnpacked *public_key) {
  uint8_t entropy[MLKEM768_ENCAPS_RANDOMNESS];
  RAND_bytes(entropy, MLKEM768_ENCAPS_RANDOMNESS);

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    // Copy m256i from key.
    Eurydice_slice key_slice = EURYDICE_SLICE(public_key->opaque.bytes, 0,
                                              sizeof(public_key->opaque.bytes));
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked key =
        libcrux_ml_kem_mlkem768_avx2_unpacked_public_key_from_bytes(key_slice);


    tuple_3c ct_zz =
        libcrux_ml_kem_mlkem768_avx2_unpacked_encapsulate(&key, &entropy[0]);

    OPENSSL_memcpy(out_ciphertext, ct_zz.fst.value, MLKEM768_CIPHERTEXTBYTES);
    OPENSSL_memcpy(out_shared_secret, ct_zz.snd, MLKEM768_SHAREDSECRETBYTES);

    return;
  }
#endif  // OPENSSL_X86_64

  tuple_3c ct_zz = libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked *)
          public_key,
      &entropy[0]);

  OPENSSL_memcpy(out_ciphertext, ct_zz.fst.value, MLKEM768_CIPHERTEXTBYTES);
  OPENSSL_memcpy(out_shared_secret, ct_zz.snd, MLKEM768_SHAREDSECRETBYTES);
}

void MlKem768_Encapsulate_ExternalEntropy(
    uint8_t out_ciphertext[MLKEM768_CIPHERTEXTBYTES],
    uint8_t out_shared_secret[MLKEM768_SHAREDSECRETBYTES],
    const struct MlKem768_PublicKeyUnpacked *public_key,
    const uint8_t entropy[MLKEM768_ENCAPS_RANDOMNESS]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    // Copy m256i from key.
    Eurydice_slice key_slice = EURYDICE_SLICE(public_key->opaque.bytes, 0,
                                              sizeof(public_key->opaque.bytes));
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768PublicKeyUnpacked key =
        libcrux_ml_kem_mlkem768_avx2_unpacked_public_key_from_bytes(key_slice);


    tuple_3c ct_zz = libcrux_ml_kem_mlkem768_avx2_unpacked_encapsulate(
        &key, (uint8_t *)&entropy[0]);

    OPENSSL_memcpy(out_ciphertext, ct_zz.fst.value, MLKEM768_CIPHERTEXTBYTES);
    OPENSSL_memcpy(out_shared_secret, ct_zz.snd, MLKEM768_SHAREDSECRETBYTES);

    return;
  }
#endif  // OPENSSL_X86_64

  tuple_3c ct_zz = libcrux_ml_kem_mlkem768_portable_unpacked_encapsulate(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768PublicKeyUnpacked *)
          public_key,
      (uint8_t *)&entropy[0]);

  OPENSSL_memcpy(out_ciphertext, ct_zz.fst.value, MLKEM768_CIPHERTEXTBYTES);
  OPENSSL_memcpy(out_shared_secret, ct_zz.snd, MLKEM768_SHAREDSECRETBYTES);
}

int Mlkem768_Decapsulate(uint8_t out_ss[MLKEM768_SHAREDSECRETBYTES],
                         const uint8_t (*ct)[MLKEM768_CIPHERTEXTBYTES],
                         const uint8_t (*sk)[MLKEM768_SECRETKEYBYTES]) {
  libcrux_ml_kem_types_MlKemPrivateKey_55 secret_key;
  memcpy(secret_key.value, sk, MLKEM768_SECRETKEYBYTES);

  libcrux_ml_kem_mlkem768_MlKem768Ciphertext cipher_text;
  memcpy(cipher_text.value, ct, MLKEM768_CIPHERTEXTBYTES);


  bool valid = libcrux_ml_kem_mlkem768_portable_validate_private_key(
      &secret_key, &cipher_text);
  if (!valid) {
    // The private key is invalid, abort.
    return 0;
  }

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    libcrux_ml_kem_mlkem768_avx2_decapsulate(&secret_key, &cipher_text, out_ss);
  }
  return 1;
#endif  // OPENSSL_X86_64

  libcrux_ml_kem_mlkem768_portable_decapsulate(&secret_key, &cipher_text,
                                               out_ss);
  return 1;
}

int MlKem768_Decapsulate(uint8_t out_shared_secret[MLKEM768_SHAREDSECRETBYTES],
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         const struct MlKem768_KeyPairUnpacked *private_key) {
  if (ciphertext_len != MLKEM768_CIPHERTEXTBYTES) {
    return 0;
  }

  libcrux_ml_kem_mlkem768_MlKem768Ciphertext cipher_text;
  OPENSSL_memcpy(cipher_text.value, ciphertext, MLKEM768_CIPHERTEXTBYTES);

#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
    // Copy m256i from key.
    Eurydice_slice key_slice = EURYDICE_SLICE(
        private_key->opaque.bytes, 0, sizeof(private_key->opaque.bytes));
    libcrux_ml_kem_mlkem768_avx2_unpacked_MlKem768KeyPairUnpacked keys =
        libcrux_ml_kem_mlkem768_avx2_unpacked_key_pair_from_bytes(key_slice);


    libcrux_ml_kem_mlkem768_avx2_unpacked_decapsulate(&keys, &cipher_text,
                                                      out_shared_secret);

    return 1;
  }
#endif  // OPENSSL_X86_64

  libcrux_ml_kem_mlkem768_portable_unpacked_decapsulate(
      (libcrux_ml_kem_mlkem768_portable_unpacked_MlKem768KeyPairUnpacked *)
          private_key,
      &cipher_text, out_shared_secret);

  return 1;
}
