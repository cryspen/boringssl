/*
  This file was generated by KaRaMeL <https://github.com/FStarLang/karamel>
  KaRaMeL invocation: /home/franziskus/eurydice//eurydice --config ../c.yaml
  ../../libcrux_ml_kem.llbc ../../libcrux_sha3.llbc F* version: <unknown>
  KaRaMeL version: 22425a93
 */

#ifndef __libcrux_mlkem512_portable_H
#define __libcrux_mlkem512_portable_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "eurydice_glue.h"
#include "libcrux_core.h"

void libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate___2size_t_1632size_t_768size_t_800size_t_768size_t_768size_t_640size_t_128size_t_10size_t_4size_t_320size_t_3size_t_192size_t_2size_t_128size_t_800size_t(
    libcrux_ml_kem_types_MlKemPrivateKey____1632size_t *private_key,
    libcrux_ml_kem_types_MlKemCiphertext____768size_t *ciphertext,
    uint8_t ret[32U]);

void libcrux_ml_kem_mlkem512_portable_decapsulate(
    libcrux_ml_kem_types_MlKemPrivateKey____1632size_t *private_key,
    libcrux_ml_kem_types_MlKemCiphertext____768size_t *ciphertext,
    uint8_t ret[32U]);

K___libcrux_ml_kem_types_MlKemCiphertext___768size_t___uint8_t_32size_t_
libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate___2size_t_768size_t_800size_t_768size_t_640size_t_128size_t_10size_t_4size_t_320size_t_3size_t_192size_t_2size_t_128size_t(
    libcrux_ml_kem_types_MlKemPublicKey____800size_t *public_key,
    uint8_t randomness[32U]);

K___libcrux_ml_kem_types_MlKemCiphertext___768size_t___uint8_t_32size_t_
libcrux_ml_kem_mlkem512_portable_encapsulate(
    libcrux_ml_kem_types_MlKemPublicKey____800size_t *public_key,
    uint8_t randomness[32U]);

libcrux_ml_kem_types_MlKemKeyPair____1632size_t__800size_t
libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair___2size_t_768size_t_1632size_t_800size_t_768size_t_3size_t_192size_t(
    uint8_t randomness[64U]);

libcrux_ml_kem_types_MlKemKeyPair____1632size_t__800size_t
libcrux_ml_kem_mlkem512_portable_generate_key_pair(uint8_t randomness[64U]);

bool libcrux_ml_kem_ind_cca_instantiations_portable_validate_public_key___2size_t_768size_t_800size_t(
    uint8_t *public_key);

core_option_Option__libcrux_ml_kem_types_MlKemPublicKey___800size_t__
libcrux_ml_kem_mlkem512_portable_validate_public_key(
    libcrux_ml_kem_types_MlKemPublicKey____800size_t public_key);

bool libcrux_ml_kem_ind_cca_instantiations_portable_validate_public_key___4size_t_1536size_t_1568size_t(
    uint8_t *public_key);

libcrux_ml_kem_mlkem1024_MlKem1024KeyPair
libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair___4size_t_1536size_t_3168size_t_1568size_t_1536size_t_2size_t_128size_t(
    uint8_t randomness[64U]);

K___libcrux_ml_kem_types_MlKemCiphertext___1568size_t___uint8_t_32size_t_
libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate___4size_t_1568size_t_1568size_t_1536size_t_1408size_t_160size_t_11size_t_5size_t_352size_t_2size_t_128size_t_2size_t_128size_t(
    libcrux_ml_kem_types_MlKemPublicKey____1568size_t *public_key,
    uint8_t randomness[32U]);

void libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate___4size_t_3168size_t_1536size_t_1568size_t_1568size_t_1536size_t_1408size_t_160size_t_11size_t_5size_t_352size_t_2size_t_128size_t_2size_t_128size_t_1600size_t(
    libcrux_ml_kem_types_MlKemPrivateKey____3168size_t *private_key,
    libcrux_ml_kem_mlkem1024_MlKem1024Ciphertext *ciphertext, uint8_t ret[32U]);

bool libcrux_ml_kem_ind_cca_instantiations_portable_validate_public_key___3size_t_1152size_t_1184size_t(
    uint8_t *public_key);

libcrux_ml_kem_mlkem768_MlKem768KeyPair
libcrux_ml_kem_ind_cca_instantiations_portable_generate_keypair___3size_t_1152size_t_2400size_t_1184size_t_1152size_t_2size_t_128size_t(
    uint8_t randomness[64U]);

K___libcrux_ml_kem_types_MlKemCiphertext___1088size_t___uint8_t_32size_t_
libcrux_ml_kem_ind_cca_instantiations_portable_encapsulate___3size_t_1088size_t_1184size_t_1152size_t_960size_t_128size_t_10size_t_4size_t_320size_t_2size_t_128size_t_2size_t_128size_t(
    libcrux_ml_kem_types_MlKemPublicKey____1184size_t *public_key,
    uint8_t randomness[32U]);

void libcrux_ml_kem_ind_cca_instantiations_portable_decapsulate___3size_t_2400size_t_1152size_t_1184size_t_1088size_t_1152size_t_960size_t_128size_t_10size_t_4size_t_320size_t_2size_t_128size_t_2size_t_128size_t_1120size_t(
    libcrux_ml_kem_types_MlKemPrivateKey____2400size_t *private_key,
    libcrux_ml_kem_mlkem768_MlKem768Ciphertext *ciphertext, uint8_t ret[32U]);

#if defined(__cplusplus)
}
#endif

#define __libcrux_mlkem512_portable_H_DEFINED
#endif
