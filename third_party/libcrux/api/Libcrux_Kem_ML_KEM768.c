#include <string.h>

#include "crypto/internal.h"

#include "Libcrux_Kem_ML_KEM768.h"
#include "libcrux_mlkem768_portable.h"
#include "libcrux_sha3.h"

#if defined(__AVX2__)
#include "libcrux_mlkem768_avx2.h"
#endif

void Libcrux_Kyber768_GenerateKeyPair(uint8_t *pk, uint8_t *sk,
                                      uint8_t randomness[64]) {
#ifdef OPENSSL_X86_64
  if (CRYPTO_is_AVX2_capable()) {
  }
#else
  libcrux_ml_kem_mlkem768_MlKem768KeyPair result =
      libcrux_ml_kem_mlkem768_portable_generate_key_pair(randomness);
#endif  // OPENSSL_X86_64

  memcpy(pk, result.pk.value, MLKEM768_PUBLICKEYBYTES);
  memcpy(sk, result.sk.value, MLKEM768_SECRETKEYBYTES);
}

void Libcrux_Kyber768_Encapsulate(uint8_t *ct, uint8_t *ss, uint8_t (*pk)[1184],
                                  uint8_t randomness[32]) {
  K___libcrux_ml_kem_types_MlKemCiphertext___1088size_t___uint8_t_32size_t_
      result = libcrux_ml_kem_mlkem768_portable_encapsulate(
          (libcrux_ml_kem_types_MlKemPublicKey____1184size_t *)pk, randomness);

  memcpy(ct, result.fst.value, MLKEM768_CIPHERTEXTBYTES);
  memcpy(ss, result.snd, MLKEM768_SHAREDSECRETBYTES);
}

void Libcrux_Kyber768_Decapsulate(uint8_t ss[32U], uint8_t (*ct)[1088U],
                                  uint8_t (*sk)[2400U]) {
  // Alternatives: memcpy or changing the libcrux API to take the pointer.
  libcrux_ml_kem_mlkem768_portable_decapsulate(
      (libcrux_ml_kem_types_MlKemPrivateKey____2400size_t *)sk,
      (libcrux_ml_kem_mlkem768_MlKem768Ciphertext *)ct, ss);
}

void Libcrux_Sha3_256(uint8_t *input, size_t len, uint8_t (*ret)[32]) {
  libcrux_sha3_sha256(EURYDICE_SLICE(input, 0, len), (uint8_t *)ret);
}
