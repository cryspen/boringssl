/*
 * SPDX-FileCopyrightText: 2024 Eurydice Contributors
 * SPDX-FileCopyrightText: 2024 - 2025 Cryspen Sarl <info@cryspen.com>
 *
 * SPDX-License-Identifier: MIT or Apache-2.0
 */

// Note that the Rust code must check, either at runtime or with verification,
// that any arithmetic in this file does overflow, underflow, or run out of
// bounds.
//
// TODO(crbug.com/404286922): Use designated initializers instead of /*name=*/
// comments when switching to C++20.

#ifndef EURYDICE_HEADER_EURYDICE_GLUE_H
#define EURYDICE_HEADER_EURYDICE_GLUE_H

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KRML_HOST_EPRINTF
#define KRML_HOST_EPRINTF(...) fprintf(stderr, __VA_ARGS__)
#endif

#include <utility>

#ifdef _MSC_VER
// For __popcnt
#include <intrin.h>
#endif

#include "karamel/target.h"

// In order to be compatible with C++17 we need to work around the fact that we
// can not use designated initializers. This is an issue for unions. The
// following defines `KRML_UNION_CONSTRUCTOR` for this purpose.
// This is used in union definitions such as
// ```c
// typedef struct Result_s {
//  uint8_t tag;
//  union U {
//    int16_t case_Ok[16U];
//    uint8_t case_Err;
//  } val;
//  KRML_UNION_CONSTRUCTOR(Result_s)
//} Result_0a;
// ```

#ifndef __cpp_lib_type_identity
template <class T>
struct type_identity {
  using type = T;
};

template <class T>
using type_identity_t = typename type_identity<T>::type;
#else
using std::type_identity_t;
#endif

#define KRML_UNION_CONSTRUCTOR(T)                              \
  template <typename V>                                        \
  constexpr T(int t, V U::*m, type_identity_t<V> v) : tag(t) { \
    val.*m = std::move(v);                                     \
  }                                                            \
  T() = default;

// GENERAL-PURPOSE STUFF


// SLICES, ARRAYS, ETC.

// For convenience, we give these common slice types, below, a distinguished
// status and rather than emit them in the client code, we skip their
// code-generation in Cleanup3.ml and write them by hand here. This makes it
// easy to write interop code that brings those definitions in scope.

// &[u8]
typedef struct Eurydice_borrow_slice_u8_s {
  const uint8_t *ptr;
  size_t meta;
} Eurydice_borrow_slice_u8;

// &[i16]
typedef struct Eurydice_borrow_slice_i16_s {
  const int16_t *ptr;
  size_t meta;
} Eurydice_borrow_slice_i16;

// &mut [u8]
typedef struct Eurydice_mut_borrow_slice_u8_s {
  uint8_t *ptr;
  size_t meta;
} Eurydice_mut_borrow_slice_u8;

// &mut [i16]
typedef struct Eurydice_mut_borrow_slice_i16_s {
  int16_t *ptr;
  size_t meta;
} Eurydice_mut_borrow_slice_i16;

#if defined(__cplusplus)
#define KRML_CLITERAL(type) type
#else
#define KRML_CLITERAL(type) (type)
#endif

#if defined(__cplusplus) && defined(__cpp_designated_initializers) || \
    !(defined(__cplusplus))
#define EURYDICE_CFIELD(X) X
#else
#define EURYDICE_CFIELD(X)
#endif

// Slice length
#define Eurydice_slice_len(s, _) (s).meta

#define Eurydice_slice_index_mut(s, i, t) ((s).ptr[i])
#define Eurydice_slice_index_shared(s, i, t) ((s).ptr[i])


// The following functions get sub slices from a slice.

// Variant for when the start and end indices are statically known (i.e., the
// range argument `r` is a literal).
// Previous version above does not work when t is an array type (as usual). Will
// be deprecated soon.
// The following functions convert an array into a slice.

// Same as above, variant for when start and end are statically known
// Same as above, variant for when start and end are statically known
// Copy a slice with memcpy
#define Eurydice_slice_copy(dst, src, t) \
  memcpy(dst.ptr, src.ptr, dst.meta * sizeof(t))

#define core_array___Array_T__N___as_slice(len_, ptr_, t, ret_t) \
  (KRML_CLITERAL(ret_t){EURYDICE_CFIELD(.ptr =)(ptr_)->data,     \
                        EURYDICE_CFIELD(.meta =) len_})

#define core_array__core__clone__Clone_for__Array_T__N___clone( \
    len, src, elem_type, _ret_t)                                \
  (*(src))
#define TryFromSliceError uint8_t
#define core_array_TryFromSliceError uint8_t

// Compare two arrays with `memcmp`.
#define Eurydice_array_eq(sz, a1, a2, t) (memcmp(a1, a2, sz * sizeof(t)) == 0)

// core::cmp::PartialEq<&0 (@Slice<U>)> for @Array<T, N>
#define Eurydice_array_eq_slice(sz, a1, s2, t, _) \
  (memcmp(a1, (s2)->ptr, sz * sizeof(t)) == 0)


#define Eurydice_slice_split_at(slice, mid, element_type, ret_t)        \
  KRML_CLITERAL(ret_t) {                                                \
    EURYDICE_CFIELD(.fst =){EURYDICE_CFIELD(.ptr =)((slice).ptr),       \
                            EURYDICE_CFIELD(.meta =) mid},              \
        EURYDICE_CFIELD(.snd =) {                                       \
      EURYDICE_CFIELD(.ptr =)                                           \
      ((slice).ptr + mid), EURYDICE_CFIELD(.meta =)((slice).meta - mid) \
    }                                                                   \
  }



// SUPPORT FOR DSTs (Dynamically-Sized Types)

// A DST is a fat pointer that keeps tracks of the size of it flexible array
// member. Slices are a specific case of DSTs, where [T; N] implements
// Unsize<[T]>, meaning an array of statically known size can be converted to a
// fat pointer, i.e. a slice.
//
// Unlike slices, DSTs have a built-in definition that gets monomorphized, of
// the form:
//
// typedef struct {
//   T *ptr;
//   size_t len; // number of elements
// } Eurydice_dst;
//
// Furthermore, T = T0<[U0]> where `struct T0<U: ?Sized>`, where the `U` is the
// last field. This means that there are two monomorphizations of T0 in the
// program. One is `T0<[V; N]>`
// -- this is directly converted to a Eurydice_dst via suitable codegen (no
// macro). The other is `T = T0<[U]>`, where `[U]` gets emitted to
// `Eurydice_derefed_slice`, a type that only appears in that precise situation
// and is thus defined to give rise to a flexible array member.

typedef char Eurydice_derefed_slice[];

// CORE STUFF (conversions, endianness, ...)

// [ u8; 2 ]
typedef struct Eurydice_array_u8x2_s {
  uint8_t data[2];
} Eurydice_array_u8x2;

// [ u8; 8 ]
typedef struct Eurydice_array_u8x8_s {
  uint8_t data[8];
} Eurydice_array_u8x8;

static inline Eurydice_array_u8x8 core_num__u64__to_le_bytes(uint64_t v) {
  Eurydice_array_u8x8 out;
  CRYPTO_store_u64_le(&out.data, v);
  return out;
}

static inline uint64_t core_num__u64__from_le_bytes(Eurydice_array_u8x8 buf) {
  return CRYPTO_load_u64_le(buf.data);
}

static inline uint32_t core_num__u8__count_ones(uint8_t x0) {
#ifdef _MSC_VER
  return __popcnt(x0);
#else
  return __builtin_popcount(x0);
#endif
}

// unsigned overflow wraparound semantics in C
static inline uint16_t core_num__u16__wrapping_add(uint16_t x, uint16_t y) {
  return x + y;
}
static inline uint8_t core_num__u8__wrapping_sub(uint8_t x, uint8_t y) {
  return x - y;
}
static inline uint64_t core_num__u64__rotate_left(uint64_t value,
                                                  uint32_t shift) {
  return CRYPTO_rotl_u64(value, shift);
}

#endif /* EURYDICE_HEADER_EURYDICE_GLUE_H */
