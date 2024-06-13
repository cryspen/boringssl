#ifndef __libcrux_intrinsics_avx2_H
#define __libcrux_intrinsics_avx2_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "eurydice_glue.h"
#include "immintrin.h"

typedef __m128i core_core_arch_x86___m128i;
typedef __m256i core_core_arch_x86___m256i;

// Cast and Convert

static inline core_core_arch_x86___m128i
libcrux_intrinsics_avx2_mm256_castsi256_si128(core_core_arch_x86___m256i a) {
  return _mm256_castsi256_si128(a);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_cvtepi16_epi32(core_core_arch_x86___m128i a) {
  return _mm256_cvtepi16_epi32(a);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_castsi128_si256(core_core_arch_x86___m128i a) {
  return _mm256_castsi128_si256(a);
}

// Initialize, Load, Store

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_setzero_si256(void) {
  return _mm256_setzero_si256();
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_set1_epi16(int16_t a) {
  return _mm256_set1_epi16(a);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_set1_epi32(int32_t a) {
  return _mm256_set1_epi32(a);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_set1_epi64x(int64_t a) {
  return _mm256_set1_epi64x(a);
}

static inline core_core_arch_x86___m128i libcrux_intrinsics_avx2_mm_set1_epi16(
    int16_t a) {
  return _mm_set1_epi16(a);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_set_epi16(int16_t x0, int16_t x1, int16_t x2,
                                        int16_t x3, int16_t x4, int16_t x5,
                                        int16_t x6, int16_t x7, int16_t x8,
                                        int16_t x9, int16_t x10, int16_t x11,
                                        int16_t x12, int16_t x13, int16_t x14,
                                        int16_t x15) {
  return _mm256_set_epi16(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12,
                          x13, x14, x15);
}

static inline core_core_arch_x86___m256i libcrux_intrinsics_avx2_mm256_set_epi8(
    int8_t x0, int8_t x1, int8_t x2, int8_t x3, int8_t x4, int8_t x5, int8_t x6,
    int8_t x7, int8_t x8, int8_t x9, int8_t x10, int8_t x11, int8_t x12,
    int8_t x13, int8_t x14, int8_t x15, int8_t x16, int8_t x17, int8_t x18,
    int8_t x19, int8_t x20, int8_t x21, int8_t x22, int8_t x23, int8_t x24,
    int8_t x25, int8_t x26, int8_t x27, int8_t x28, int8_t x29, int8_t x30,
    int8_t x31) {
  return _mm256_set_epi8(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12,
                         x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23,
                         x24, x25, x26, x27, x28, x29, x30, x31);
}

static inline core_core_arch_x86___m128i libcrux_intrinsics_avx2_mm_set_epi8(
    uint8_t x0, uint8_t x1, uint8_t x2, uint8_t x3, uint8_t x4, uint8_t x5,
    uint8_t x6, uint8_t x7, uint8_t x8, uint8_t x9, uint8_t x10, uint8_t x11,
    uint8_t x12, uint8_t x13, uint8_t x14, uint8_t x15) {
  return _mm_set_epi8(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12,
                      x13, x14, x15);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_set_epi32(int32_t x0, int32_t x1, int32_t x2,
                                        int32_t x3, int32_t x4, int32_t x5,
                                        int32_t x6, int32_t x7) {
  return _mm256_set_epi32(x0, x1, x2, x3, x4, x5, x6, x7);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_loadu_si256_i16(Eurydice_slice a) {
  return _mm256_loadu_si256((const __m256i *)a.ptr);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_loadu_si256_u8(Eurydice_slice a) {
  return _mm256_loadu_si256((const __m256i *)a.ptr);
}

static inline core_core_arch_x86___m128i libcrux_intrinsics_avx2_mm_loadu_si128(
    Eurydice_slice a) {
  return _mm_loadu_si128((const __m128i *)a.ptr);
}

static inline void libcrux_intrinsics_avx2_mm_storeu_bytes_si128(
    Eurydice_slice a, core_core_arch_x86___m128i b) {
  _mm_storeu_si128((__m128i *)a.ptr, b);
}

static inline void libcrux_intrinsics_avx2_mm256_storeu_si256_i16(
    Eurydice_slice a, core_core_arch_x86___m256i b) {
  _mm256_storeu_si256((__m256i *)a.ptr, b);
}

static inline void libcrux_intrinsics_avx2_mm256_storeu_si256_u8(
    Eurydice_slice a, core_core_arch_x86___m256i b) {
  _mm256_storeu_si256((__m256i *)a.ptr, b);
}

static inline void libcrux_intrinsics_avx2_mm_storeu_si128(
    Eurydice_slice a, core_core_arch_x86___m128i b) {
  _mm_storeu_si128((__m128i *)a.ptr, b);
}

// Arithmetic: Add, Sub

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_add_epi16(core_core_arch_x86___m256i a,
                                        core_core_arch_x86___m256i b) {
  return _mm256_add_epi16(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_add_epi32(core_core_arch_x86___m256i a,
                                        core_core_arch_x86___m256i b) {
  return _mm256_add_epi32(a, b);
}

static inline core_core_arch_x86___m128i libcrux_intrinsics_avx2_mm_add_epi16(
    core_core_arch_x86___m128i a, core_core_arch_x86___m128i b) {
  return _mm_add_epi16(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_sub_epi16(core_core_arch_x86___m256i a,
                                        core_core_arch_x86___m256i b) {
  return _mm256_sub_epi16(a, b);
}

static inline core_core_arch_x86___m128i libcrux_intrinsics_avx2_mm_sub_epi16(
    core_core_arch_x86___m128i a, core_core_arch_x86___m128i b) {
  return _mm_sub_epi16(a, b);
}

// Arithmetic: Mul low and high, Mul-Add combinations

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_mullo_epi16(core_core_arch_x86___m256i a,
                                          core_core_arch_x86___m256i b) {
  return _mm256_mullo_epi16(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_mulhi_epi16(core_core_arch_x86___m256i a,
                                          core_core_arch_x86___m256i b) {
  return _mm256_mulhi_epi16(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_mul_epu32(core_core_arch_x86___m256i a,
                                        core_core_arch_x86___m256i b) {
  return _mm256_mul_epu32(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_mullo_epi32(core_core_arch_x86___m256i a,
                                          core_core_arch_x86___m256i b) {
  return _mm256_mullo_epi32(a, b);
}

static inline core_core_arch_x86___m128i libcrux_intrinsics_avx2_mm_mullo_epi16(
    core_core_arch_x86___m128i a, core_core_arch_x86___m128i b) {
  return _mm_mullo_epi16(a, b);
}

static inline core_core_arch_x86___m128i libcrux_intrinsics_avx2_mm_mulhi_epi16(
    core_core_arch_x86___m128i a, core_core_arch_x86___m128i b) {
  return _mm_mulhi_epi16(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_madd_epi16(core_core_arch_x86___m256i a,
                                         core_core_arch_x86___m256i b) {
  return _mm256_madd_epi16(a, b);
}

// Comparison

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_cmpgt_epi16(core_core_arch_x86___m256i a,
                                          core_core_arch_x86___m256i b) {
  return _mm256_cmpgt_epi16(a, b);
}

// Bitwise operations

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_and_si256(core_core_arch_x86___m256i a,
                                        core_core_arch_x86___m256i b) {
  return _mm256_and_si256(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_andnot_si256(core_core_arch_x86___m256i a,
                                           core_core_arch_x86___m256i b) {
  return _mm256_andnot_si256(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_xor_si256(core_core_arch_x86___m256i a,
                                        core_core_arch_x86___m256i b) {
  return _mm256_xor_si256(a, b);
}

static inline int32_t libcrux_intrinsics_avx2_mm_movemask_epi8(
    core_core_arch_x86___m128i a) {
  return _mm_movemask_epi8(a);
}

// Shift operations
#define libcrux_intrinsics_avx2_mm256_srai_epi16(a, b, _) \
  (_mm256_srai_epi16(b, a))

#define libcrux_intrinsics_avx2_mm256_srli_epi16(a, b, _) \
  (_mm256_srli_epi16(b, a))

#define libcrux_intrinsics_avx2_mm256_slli_epi16(a, b, _) \
  (_mm256_slli_epi16(b, a))

#define libcrux_intrinsics_avx2_mm256_slli_epi32(a, b, _) \
  (_mm256_slli_epi32(b, a))

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_slli_epi64_(int32_t a,
                                          core_core_arch_x86___m256i b) {
  return _mm256_slli_epi64(b, a);
}

#define libcrux_intrinsics_avx2_mm256_slli_epi64(a, b, c) \
  (libcrux_intrinsics_avx2_mm256_slli_epi64_(a, b))

#define libcrux_intrinsics_avx2_mm256_srai_epi32(a, b, _) \
  (_mm256_srai_epi32(b, a))

#define libcrux_intrinsics_avx2_mm256_srli_epi32(a, b, _) \
  (_mm256_srli_epi32(b, a))

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_sllv_epi32(core_core_arch_x86___m256i a,
                                         core_core_arch_x86___m256i b) {
  return _mm256_sllv_epi32(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_srli_epi64_(int32_t a,
                                          core_core_arch_x86___m256i b) {
  return _mm256_srli_epi64(b, a);
}

#define libcrux_intrinsics_avx2_mm256_srli_epi64(a, b, c) \
  (libcrux_intrinsics_avx2_mm256_srli_epi64_(a, b))

// Shuffle and Vector Interleaving

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_unpacklo_epi32(core_core_arch_x86___m256i a,
                                             core_core_arch_x86___m256i b) {
  return _mm256_unpacklo_epi32(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_unpacklo_epi64(core_core_arch_x86___m256i a,
                                             core_core_arch_x86___m256i b) {
  return _mm256_unpacklo_epi64(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_unpackhi_epi32(core_core_arch_x86___m256i a,
                                             core_core_arch_x86___m256i b) {
  return _mm256_unpackhi_epi32(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_unpackhi_epi64(core_core_arch_x86___m256i a,
                                             core_core_arch_x86___m256i b) {
  return _mm256_unpackhi_epi64(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_packs_epi32(core_core_arch_x86___m256i a,
                                          core_core_arch_x86___m256i b) {
  return _mm256_packs_epi32(a, b);
}

static inline core_core_arch_x86___m128i libcrux_intrinsics_avx2_mm_packs_epi16(
    core_core_arch_x86___m128i a, core_core_arch_x86___m128i b) {
  return _mm_packs_epi16(a, b);
}

#define libcrux_intrinsics_avx2_mm256_shuffle_epi32(a, b, _) \
  (_mm256_shuffle_epi32(b, a))

#define libcrux_intrinsics_avx2_mm256_extracti128_si256(a, b, _) \
  (_mm256_extracti128_si256(b, a))

#define libcrux_intrinsics_avx2_mm256_permute4x64_epi64(a, b, _) \
  (_mm256_permute4x64_epi64(b, a))

#define libcrux_intrinsics_avx2_mm256_permute2x128_si256(a, b, c, d) \
  (_mm256_permute2x128_si256(b, c, a))

#define libcrux_intrinsics_avx2_mm256_inserti128_si256(a, b, c, _) \
  (_mm256_inserti128_si256(b, c, a))

#define libcrux_intrinsics_avx2_mm256_blend_epi16(a, b, c, _) \
  (_mm256_blend_epi16(b, c, a))

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_shuffle_epi8(core_core_arch_x86___m256i a,
                                           core_core_arch_x86___m256i b) {
  return _mm256_shuffle_epi8(a, b);
}

static inline core_core_arch_x86___m256i
libcrux_intrinsics_avx2_mm256_permutevar8x32_epi32(
    core_core_arch_x86___m256i a, core_core_arch_x86___m256i b) {
  return _mm256_permutevar8x32_epi32(a, b);
}

static inline core_core_arch_x86___m128i
libcrux_intrinsics_avx2_mm_shuffle_epi8(core_core_arch_x86___m128i a,
                                        core_core_arch_x86___m128i b) {
  return _mm_shuffle_epi8(a, b);
}

#if defined(__cplusplus)
}
#endif

#define __libcrux_intrinsics_avx2_H_DEFINED
#endif
