#ifndef __Libcrux_Kem_Kyber_Mlkem768_H
#define __Libcrux_Kem_Kyber_Mlkem768_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>

#include "base.h"

#define MLKEM768_SECRETKEYBYTES 2400
#define MLKEM768_PUBLICKEYBYTES 1184
#define MLKEM768_CIPHERTEXTBYTES 1088
#define MLKEM768_SHAREDSECRETBYTES 32
#define MLKEM768_KEY_GENERATION_RANDOMNESS 64
#define MLKEM768_ENCAPS_RANDOMNESS 32

#define MLKEM768_UNPACKED_PUBLIC_KEY_SIZE \
  (32 + 3 * 16 * 32 + 32 + 3 * 3 * 16 * 32)
#define MLKEM768_UNPACKED_PRIVATE_KEY_SIZE (3 * 16 * 32 + 32)

struct MlKem768_KeyPairUnpacked {
  union {
    uint8_t bytes[MLKEM768_UNPACKED_PUBLIC_KEY_SIZE +
                  MLKEM768_UNPACKED_PRIVATE_KEY_SIZE];
    uint16_t alignment;
  } opaque;
};

struct MlKem768_PublicKeyUnpacked {
  union {
    uint8_t bytes[MLKEM768_UNPACKED_PUBLIC_KEY_SIZE];
    uint16_t alignment;
  } opaque;
};

// Mlkem768_GenerateKeyPair generates a random public/private key pair, writes
// the encoded public key to |out_pk| and sets |out_sk| to the encoded the
// private key.
//
// |out_pk| must point to MLKEM768_PUBLICKEYBYTES bytes of memory
// |out_sk| must point to MLKEM768_SECRETKEYBYTES bytes of memory
OPENSSL_EXPORT void Mlkem768_GenerateKeyPair(
    uint8_t *out_pk, uint8_t *out_sk,
    const uint8_t randomness[MLKEM768_KEY_GENERATION_RANDOMNESS]);

// Mlkem768_GenerateKeyPairUnpacked generates a random public/private key pair,
// writes the encoded public key to |out_encoded_public_key| and sets
// |out_key_pair| to the private key. If |optional_out_seed| is not NULL then
// the seed used to generate the private key is written to it.
OPENSSL_EXPORT void Mlkem768_GenerateKeyPairUnpacked(
    uint8_t out_encoded_public_key[MLKEM768_PUBLICKEYBYTES],
    uint8_t optional_out_seed[MLKEM768_KEY_GENERATION_RANDOMNESS],
    struct MlKem768_KeyPairUnpacked *out_key_pair);

// Mlkem768_GenerateKeyPairUnpacked_from_seed derives a private key from a seed
// that was generated by |MLKEM768_generate_key|. It fails and returns 0 if
// |seed_len| is incorrect, otherwise it writes |*out_key_pair| and
// returns 1.
OPENSSL_EXPORT int Mlkem768_GenerateKeyPairUnpacked_FromSeed(
    struct MlKem768_KeyPairUnpacked *out_key_pair, const uint8_t *seed,
    size_t seed_len);

// MlKem768_PublicKey sets |*out_public_key| to the public key of the key pair.
OPENSSL_EXPORT void MlKem768_PublicKey(
    struct MlKem768_PublicKeyUnpacked *out_public_key,
    const struct MlKem768_KeyPairUnpacked *key_pair);

// Mlkem768_Encapsulate encrypts a random shared secret for |pk|, writes the
// ciphertext to |out_ct|, and writes the random shared secret to |out_ss|.
//
// |out_ct| must point to MLKEM768_CIPHERTEXTBYTES bytes of memory
// |out_ss| must point to MLKEM768_SHAREDSECRETBYTES bytes of memory
//
// The function returns one on success or zero on if the public key is invalid.
OPENSSL_EXPORT int Mlkem768_Encapsulate(
    uint8_t *out_ct, uint8_t *out_ss,
    const uint8_t (*pk)[MLKEM768_PUBLICKEYBYTES],
    const uint8_t randomness[MLKEM768_ENCAPS_RANDOMNESS]);

// Mlkem768_ParsePublicKey parses a public key, in the format generated by
// |MLKEM768_marshal_public_key|, from |in| and writes the result to
// |out_public_key|. It returns one on success or zero on parse error or if
// the key is invalid.
OPENSSL_EXPORT int Mlkem768_ParsePublicKey(
    struct MlKem768_PublicKeyUnpacked *out_public_key, CBS *in);

// Mlkem768_MarshalPublicKey serializes |public_key| to |out| in the standard
// format for ML-KEM-768 public keys. It returns one on success or zero on
// allocation error.
OPENSSL_EXPORT int Mlkem768_MarshalPublicKey(
    CBB *out, const struct MlKem768_PublicKeyUnpacked *public_key);

// MLKEM768_encap encrypts a random shared secret for |public_key|, writes the
// ciphertext to |out_ciphertext|, and writes the random shared secret to
// |out_shared_secret|.
OPENSSL_EXPORT void MlKem768_Encapsulate(
    uint8_t out_ciphertext[MLKEM768_CIPHERTEXTBYTES],
    uint8_t out_shared_secret[MLKEM768_SHAREDSECRETBYTES],
    const struct MlKem768_PublicKeyUnpacked *public_key);

// MLKEM768_encap encrypts a random shared secret for |public_key|, writes the
// ciphertext to |out_ciphertext|, and writes the random shared secret to
// |out_shared_secret|. This function is deterministic and takes the required
// |entropy| as input.
OPENSSL_EXPORT void MlKem768_Encapsulate_ExternalEntropy(
    uint8_t out_ciphertext[MLKEM768_CIPHERTEXTBYTES],
    uint8_t out_shared_secret[MLKEM768_SHAREDSECRETBYTES],
    const struct MlKem768_PublicKeyUnpacked *public_key,
    const uint8_t entropy[MLKEM768_ENCAPS_RANDOMNESS]);

// Mlkem768_Decapsulate decrypts a shared secret from |ct| using |sk| and writes
// it to |out_ss|. If |ct| is invalid, |out_ss| is filled with a key that will
// always be the same for the same |ct| and |sk|, but which appears to be random
// unless one has access to |sk|. These alternatives occur in constant time. Any
// subsequent symmetric encryption using |out_ss| must use an authenticated
// encryption scheme in order to discover the decapsulation failure.
//
// The function returns one on success or zero on if the private key is invalid.
OPENSSL_EXPORT int Mlkem768_Decapsulate(
    uint8_t out_ss[MLKEM768_SHAREDSECRETBYTES],
    const uint8_t (*ct)[MLKEM768_CIPHERTEXTBYTES],
    const uint8_t (*sk)[MLKEM768_SECRETKEYBYTES]);

// MLKEM768_decap decrypts a shared secret from |ciphertext| using |private_key|
// and writes it to |out_shared_secret|. If |ciphertext_len| is incorrect, it
// returns 0, otherwise it returns 1. If |ciphertext| is invalid (but of the
// correct length), |out_shared_secret| is filled with a key that will always be
// the same for the same |ciphertext| and |private_key|, but which appears to be
// random unless one has access to |private_key|. These alternatives occur in
// constant time. Any subsequent symmetric encryption using |out_shared_secret|
// must use an authenticated encryption scheme in order to discover the
// decapsulation failure.
OPENSSL_EXPORT int MlKem768_Decapsulate(
    uint8_t out_shared_secret[MLKEM768_SHAREDSECRETBYTES],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const struct MlKem768_KeyPairUnpacked *private_key);

#if defined(__cplusplus)
}
#endif

#define __Libcrux_Kem_Kyber_Mlkem768_H_DEFINED
#endif