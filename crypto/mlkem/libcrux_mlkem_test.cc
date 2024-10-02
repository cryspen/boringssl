#include <gtest/gtest.h>
#include <fstream>

#include <openssl/bytestring.h>
#include <openssl/mlkem.h>

#include "../keccak/internal.h"
#include "../test/file_test.h"
#include "../test/test_util.h"
#include "internal.h"

using namespace std;

typedef vector<uint8_t> bytes;

template <typename T>
std::vector<uint8_t> Marshal(int (*marshal_func)(CBB *, const T *),
                             const T *t) {
  bssl::ScopedCBB cbb;
  uint8_t *encoded;
  size_t encoded_len;
  if (!CBB_init(cbb.get(), 1) ||      //
      !marshal_func(cbb.get(), t) ||  //
      !CBB_finish(cbb.get(), &encoded, &encoded_len)) {
    abort();
  }

  std::vector<uint8_t> ret(encoded, encoded + encoded_len);
  OPENSSL_free(encoded);
  return ret;
}

static inline void ctwrap_decaps(
    uint8_t out_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES],
    MLKEM768_private_key *secret_key) {
  uint8_t ct[MLKEM768_CIPHERTEXT_BYTES];
  MLKEM768_private_key sk;

  // Copy all the secrets into a temporary buffer, so we can run constant-time
  // validation on them.
  OPENSSL_memcpy(ct, ciphertext, MLKEM768_CIPHERTEXT_BYTES);
  OPENSSL_memcpy(&sk, secret_key, sizeof(sk));

  // ML-KEM should not leak the private key or the shared secret.
  CONSTTIME_SECRET(&sk, sizeof(sk));
  CONSTTIME_SECRET(out_shared_secret, MLKEM_SHARED_SECRET_BYTES);

  // Mark everything as secret.
  CONSTTIME_SECRET(ct, MLKEM768_CIPHERTEXT_BYTES);

  MLKEM768_decap(out_shared_secret, ct, sizeof(ct), &sk);

  CONSTTIME_DECLASSIFY(out_shared_secret, MLKEM_SHARED_SECRET_BYTES);
}

TEST(MLKEM768Test, ConsistencyTest) {
  uint8_t randomness[MLKEM_SEED_BYTES] = {0x37};
  struct MLKEM768_public_key publicKey;
  uint8_t publicKeyEncoded[MLKEM768_PUBLIC_KEY_BYTES];
  struct MLKEM768_private_key secretKey;

  MLKEM768_generate_key_external_seed(publicKeyEncoded, &secretKey, randomness);
  MLKEM768_public_from_private(&publicKey, &secretKey);

  uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES];

  uint8_t encap_randomness[MLKEM_SEED_BYTES] = {0x38};
  MLKEM768_encap_external_entropy(ciphertext, sharedSecret, &publicKey,
                                  encap_randomness);

  uint8_t sharedSecret2[MLKEM_SHARED_SECRET_BYTES];
  ctwrap_decaps(sharedSecret2, ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, MLKEM_SHARED_SECRET_BYTES));
}

static void MlkemKatFileTest(FileTest *t) {
  bytes key_generation_seed, sha3_256_hash_of_public_key,
      sha3_256_hash_of_secret_key, encapsulation_seed,
      sha3_256_hash_of_ciphertext, shared_secret;

  ASSERT_TRUE(t->GetBytes(&key_generation_seed, "key_generation_seed"));
  ASSERT_TRUE(
      t->GetBytes(&sha3_256_hash_of_public_key, "sha3_256_hash_of_public_key"));
  ASSERT_TRUE(
      t->GetBytes(&sha3_256_hash_of_secret_key, "sha3_256_hash_of_secret_key"));
  ASSERT_TRUE(t->GetBytes(&encapsulation_seed, "encapsulation_seed"));
  ASSERT_TRUE(
      t->GetBytes(&sha3_256_hash_of_ciphertext, "sha3_256_hash_of_ciphertext"));
  ASSERT_TRUE(t->GetBytes(&shared_secret, "shared_secret"));

  struct MLKEM768_public_key publicKey;
  struct MLKEM768_private_key secretKey;
  uint8_t publicKeyEncoded[MLKEM768_PUBLIC_KEY_BYTES];

  MLKEM768_generate_key_external_seed(publicKeyEncoded, &secretKey,
                                      key_generation_seed.data());
  MLKEM768_public_from_private(&publicKey, &secretKey);

  MLKEM768_private_key key_pair;
  ASSERT_TRUE(MLKEM768_private_key_from_seed(
      &key_pair, key_generation_seed.data(), key_generation_seed.size()));

  // Serialize the PK to compare with the other one.
  CBB serialized_pk;
  CBB_init(&serialized_pk, MLKEM768_PUBLIC_KEY_BYTES);
  MLKEM768_public_key unpacked_pk;
  MLKEM768_public_from_private(&unpacked_pk, &key_pair);
  ASSERT_TRUE(MLKEM768_marshal_public_key(&serialized_pk, &unpacked_pk));
  uint8_t *serialized_public_key;
  size_t encoded_len;
  CBB_finish(&serialized_pk, &serialized_public_key, &encoded_len);

  ASSERT_EQ((size_t)MLKEM768_PUBLIC_KEY_BYTES, encoded_len);
  EXPECT_EQ(Bytes(serialized_public_key, encoded_len), Bytes(publicKeyEncoded));

  OPENSSL_free(serialized_public_key);

  uint8_t pk_hash[32];
  BORINGSSL_keccak(pk_hash, sizeof(pk_hash), publicKeyEncoded,
                   sizeof(publicKeyEncoded), boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(pk_hash, sha3_256_hash_of_public_key.data(), 32));

  // Serialize the SK to compare with
  std::vector<uint8_t> serialized_secret_key =
      Marshal(MLKEM768_marshal_private_key, &key_pair);
  uint8_t sk_hash[32];
  BORINGSSL_keccak(sk_hash, sizeof(sk_hash), serialized_secret_key.data(),
                   serialized_secret_key.size(), boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(sk_hash, sha3_256_hash_of_secret_key.data(), 32));

  // Parse SK
  CBS cbs;
  CBS_init(&cbs, serialized_secret_key.data(), serialized_secret_key.size());
  auto priv2 = std::make_unique<MLKEM768_private_key>();
  ASSERT_TRUE(MLKEM768_parse_private_key(priv2.get(), &cbs));
  EXPECT_EQ(Bytes(serialized_secret_key),
            Bytes(Marshal(MLKEM768_marshal_private_key, priv2.get())));

  uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES];
  MLKEM768_encap_external_entropy(ciphertext, sharedSecret, &publicKey,
                                  encapsulation_seed.data());
  uint8_t ct_hash[32];
  BORINGSSL_keccak(ct_hash, sizeof(ct_hash), ciphertext, sizeof(ciphertext),
                   boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(ct_hash, sha3_256_hash_of_ciphertext.data(), 32));
  EXPECT_EQ(
      0, memcmp(sharedSecret, shared_secret.data(), MLKEM_SHARED_SECRET_BYTES));

  // Unpacked encaps
  uint8_t UnpackedCiphertext[MLKEM768_CIPHERTEXT_BYTES] = {0};
  uint8_t UnpackedSharedSecret[MLKEM_SHARED_SECRET_BYTES] = {0};

  CBS encoded_public_key_cbs;
  CBS_init(&encoded_public_key_cbs, publicKeyEncoded, sizeof(publicKeyEncoded));
  MLKEM768_public_key unpacked_public_key;
  ASSERT_TRUE(
      MLKEM768_parse_public_key(&unpacked_public_key, &encoded_public_key_cbs));

  MLKEM768_encap_external_entropy(UnpackedCiphertext, UnpackedSharedSecret,
                                  &unpacked_public_key,
                                  encapsulation_seed.data());

  BORINGSSL_keccak(ct_hash, sizeof(ct_hash), UnpackedCiphertext,
                   sizeof(UnpackedCiphertext), boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(ct_hash, sha3_256_hash_of_ciphertext.data(), 32));
  EXPECT_EQ(0, memcmp(UnpackedSharedSecret, shared_secret.data(),
                      MLKEM_SHARED_SECRET_BYTES));

  uint8_t sharedSecret2[MLKEM_SHARED_SECRET_BYTES];
  ctwrap_decaps(sharedSecret2, ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, MLKEM_SHARED_SECRET_BYTES));
}

TEST(MLKEM768TestKats, TestVectors) {
  FileTestGTest("crypto/mlkem/libcrux_mlkem768_kats.txt", MlkemKatFileTest);
}

// static void MlkemWycheproofKeygenFileTest(FileTest *t) {
//   bytes entropy, expected_public_key, expected_private_key;

//   t->IgnoreAttribute("comment");
//   ASSERT_TRUE(t->GetBytes(&entropy, "entropy"));
//   ASSERT_TRUE(t->GetBytes(&expected_public_key, "expected_public_key"));
//   ASSERT_TRUE(t->GetBytes(&expected_private_key, "expected_private_key"));

//   uint8_t publicKey[MLKEM768_PUBLIC_KEY_BYTES];
//   uint8_t secretKey[MLKEM768_PRIVATE_KEY_BYTES];

//   MLKEM768_generate_key_external_seed(publicKey, secretKey, entropy.data());

//   EXPECT_EQ(0, memcmp(publicKey, expected_public_key.data(),
//                       MLKEM768_PUBLIC_KEY_BYTES));
//   EXPECT_EQ(0, memcmp(secretKey, expected_private_key.data(),
//                       MLKEM768_PRIVATE_KEY_BYTES));
// }

// // TEST(MLKEM768WycheproofKeygen, TestVectors) {
// //   FileTestGTest("crypto/mlkem/keygen768_wycheproof.txt",
// //                 MlkemWycheproofKeygenFileTest);
// // }

// static void MlkemWycheproofEncapsFileTest(FileTest *t) {
//   bytes entropy, public_key, expected_ciphertext, expected_shared_secret;
//   string expected_result;

//   t->IgnoreAttribute("comment");
//   ASSERT_TRUE(t->GetBytes(&entropy, "entropy"));
//   ASSERT_TRUE(t->GetBytes(&public_key, "public_key"));
//   ASSERT_TRUE(t->GetAttribute(&expected_result, "expected_result"));
//   ASSERT_TRUE(t->GetBytes(&expected_ciphertext, "expected_ciphertext"));
//   ASSERT_TRUE(t->GetBytes(&expected_shared_secret,
//   "expected_shared_secret"));

//   uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES];
//   uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES];
//   auto ret = Mlkem768_Encapsulate(
//       ciphertext, sharedSecret,
//       reinterpret_cast<uint8_t[MLKEM768_PUBLIC_KEY_BYTES]>(public_key.data()),
//       entropy.data());

//   if (expected_result.compare("pass") == 0) {
//     EXPECT_EQ(1, ret);
//     EXPECT_EQ(0, memcmp(ciphertext, expected_ciphertext.data(),
//                         MLKEM768_CIPHERTEXT_BYTES));
//     EXPECT_EQ(0, memcmp(sharedSecret, expected_shared_secret.data(),
//                         MLKEM_SHARED_SECRET_BYTES));
//   } else {
//     EXPECT_TRUE(ret == 0 || public_key.size() != MLKEM768_PUBLIC_KEY_BYTES);
//   }
// }

// // TEST(MLKEM768WycheproofEncaps, TestVectors) {
// //   FileTestGTest("crypto/mlkem/encaps768_wycheproof.txt",
// //                 MlkemWycheproofEncapsFileTest);
// // }


// static void MlkemWycheproofDecapsFileTest(FileTest *t) {
//   bytes private_key, ciphertext, expected_shared_secret;
//   string expected_result;

//   t->IgnoreAttribute("comment");
//   ASSERT_TRUE(t->GetBytes(&private_key, "private_key"));
//   ASSERT_TRUE(t->GetBytes(&ciphertext, "ciphertext"));
//   ASSERT_TRUE(t->GetAttribute(&expected_result, "expected_result"));
//   ASSERT_TRUE(t->GetBytes(&expected_shared_secret,
//   "expected_shared_secret"));

//   if (expected_result.compare("pass") == 0) {
//     // Only passing tests here.
//     uint8_t sharedSecret[MLKEM_SHARED_SECRET_BYTES];
//     ctwrap_decaps(sharedSecret, ciphertext.data(), private_key.data());

//     EXPECT_EQ(0, memcmp(sharedSecret, expected_shared_secret.data(),
//                         MLKEM_SHARED_SECRET_BYTES));
//   } else {
//     // We don't check private keys.
//   }
// }

// // TEST(MLKEM768WycheproofDecaps, TestVectors) {
// //   FileTestGTest("crypto/mlkem/decaps768_wycheproof.txt",
// //                 MlkemWycheproofDecapsFileTest);
// // }
