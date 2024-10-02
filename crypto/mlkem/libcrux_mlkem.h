/* Copyright (c) 2024, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef BORINGSSL_MLKEM_LIBCRUX_MLKEM_H
#define BORINGSSL_MLKEM_LIBCRUX_MLKEM_H

#include "internal.h"

#if defined(__cplusplus)
extern "C" {
#endif

// mlkem.h

void MLKEM768_generate_key_libcrux(
    uint8_t out_encoded_public_key[MLKEM768_PUBLIC_KEY_BYTES],
    uint8_t optional_out_seed[MLKEM_SEED_BYTES],
    struct MLKEM768_private_key *out_private_key);

int MLKEM768_private_key_from_seed_libcrux(
    struct MLKEM768_private_key *out_private_key, const uint8_t *seed,
    size_t seed_len);

void MLKEM768_public_from_private_libcrux(
    struct MLKEM768_public_key *out_public_key,
    const struct MLKEM768_private_key *private_key);

void MLKEM768_encap_libcrux(
    uint8_t out_ciphertext[MLKEM768_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const struct MLKEM768_public_key *public_key);

int MLKEM768_decap_libcrux(
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const struct MLKEM768_private_key *private_key);

int MLKEM768_marshal_public_key_libcrux(
    CBB *out, const struct MLKEM768_public_key *public_key);

int MLKEM768_parse_public_key_libcrux(
    struct MLKEM768_public_key *out_public_key, CBS *in);

int MLKEM768_parse_private_key_libcrux(
    struct MLKEM768_private_key *out_private_key, CBS *in);

// internal.h
//
void MLKEM768_generate_key_external_seed_libcrux(
    uint8_t out_encoded_public_key[MLKEM768_PUBLIC_KEY_BYTES],
    struct MLKEM768_private_key *out_private_key,
    const uint8_t seed[MLKEM_SEED_BYTES]);

void MLKEM768_encap_external_entropy_libcrux(
    uint8_t out_ciphertext[MLKEM768_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const struct MLKEM768_public_key *public_key,
    const uint8_t entropy[MLKEM_ENCAP_ENTROPY]);

int MLKEM768_marshal_private_key_libcrux(
    CBB *out, const struct MLKEM768_private_key *private_key);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // BORINGSSL_MLKEM_LIBCRUX_MLKEM_H
