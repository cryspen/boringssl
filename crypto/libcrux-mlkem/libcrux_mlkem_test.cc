#include <gtest/gtest.h>
#include <fstream>

#include <openssl/bytestring.h>
#include <openssl/libcrux-mlkem.h>

#include "../keccak/internal.h"
#include "../test/file_test.h"
#include "../test/test_util.h"

using namespace std;

typedef vector<uint8_t> bytes;

static inline void ctwrap_decaps(
    uint8_t out_shared_secret[MLKEM768_SHAREDSECRETBYTES],
    const uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES],
    const uint8_t secret_key[MLKEM768_SECRETKEYBYTES]) {
  uint8_t ct[MLKEM768_CIPHERTEXTBYTES], sk[MLKEM768_SECRETKEYBYTES];

  // Copy all the secrets into a temporary buffer, so we can run constant-time
  // validation on them.
  OPENSSL_memcpy(ct, ciphertext, MLKEM768_CIPHERTEXTBYTES);
  OPENSSL_memcpy(sk, secret_key, MLKEM768_SECRETKEYBYTES);

  // ML-KEM should not leak the private key or the shared secret.
  CONSTTIME_SECRET(sk, MLKEM768_SECRETKEYBYTES);
  CONSTTIME_SECRET(out_shared_secret, MLKEM768_SHAREDSECRETBYTES);

  // Mark everything as secret.
  CONSTTIME_SECRET(ct, MLKEM768_CIPHERTEXTBYTES);

  Mlkem768_Decapsulate(out_shared_secret, &ct, &sk);

  CONSTTIME_DECLASSIFY(out_shared_secret, MLKEM768_SHAREDSECRETBYTES);
}

TEST(MLKEM768Test, ConsistencyTest) {
  uint8_t randomness[64] = {0x37};
  uint8_t publicKey[MLKEM768_PUBLICKEYBYTES];
  uint8_t secretKey[MLKEM768_SECRETKEYBYTES];

  Mlkem768_GenerateKeyPair(publicKey, secretKey, randomness);

  uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];

  uint8_t encap_randomness[64] = {0x38};
  Mlkem768_Encapsulate(ciphertext, sharedSecret, &publicKey, encap_randomness);

  uint8_t sharedSecret2[MLKEM768_SHAREDSECRETBYTES];
  ctwrap_decaps(sharedSecret2, ciphertext, secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, MLKEM768_SHAREDSECRETBYTES));
}

TEST(MLKEM768Test, ConsistencyTestUnpacked) {
  MlKem768_KeyPairUnpacked key_pair = {.opaque = {.bytes = {0}}};
  uint8_t encoded_public_key[MLKEM768_PUBLICKEYBYTES];
  uint8_t seed[MLKEM768_KEY_GENERATION_RANDOMNESS];

  Mlkem768_GenerateKeyPairUnpacked(encoded_public_key, seed, &key_pair);

  MlKem768_KeyPairUnpacked key_pair2;
  ASSERT_TRUE(Mlkem768_GenerateKeyPairUnpacked_FromSeed(&key_pair2, seed,
                                                        sizeof(seed)));

  CBS encoded_public_key_cbs;
  CBS_init(&encoded_public_key_cbs, encoded_public_key,
           sizeof(encoded_public_key));
  MlKem768_PublicKeyUnpacked public_key;
  ASSERT_TRUE(Mlkem768_ParsePublicKey(&public_key, &encoded_public_key_cbs));

  CBB serialized_pk;
  CBB_init(&serialized_pk, MLKEM768_PUBLICKEYBYTES);
  ASSERT_TRUE(Mlkem768_MarshalPublicKey(&serialized_pk, &public_key));
  uint8_t *serialized_public_key;
  size_t encoded_len;
  CBB_finish(&serialized_pk, &serialized_public_key, &encoded_len);

  ASSERT_EQ((size_t)MLKEM768_PUBLICKEYBYTES, encoded_len);
  ASSERT_EQ(0, memcmp(serialized_public_key, encoded_public_key, encoded_len));

  CBB serialized_pk2;
  CBB_init(&serialized_pk2, MLKEM768_PUBLICKEYBYTES);
  MlKem768_PublicKey(&public_key, &key_pair);
  ASSERT_TRUE(Mlkem768_MarshalPublicKey(&serialized_pk2, &public_key));
  CBB_finish(&serialized_pk2, &serialized_public_key, &encoded_len);

  ASSERT_EQ((size_t)MLKEM768_PUBLICKEYBYTES, encoded_len);
  ASSERT_EQ(0, memcmp(serialized_public_key, encoded_public_key, encoded_len));


  OPENSSL_free(serialized_public_key);

  uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES] = {0};
  uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES] = {0};

  MlKem768_Encapsulate(ciphertext, sharedSecret, &public_key);

  uint8_t sharedSecret2[MLKEM768_SHAREDSECRETBYTES];
  ASSERT_TRUE(MlKem768_Decapsulate(sharedSecret2, ciphertext,
                                   MLKEM768_CIPHERTEXTBYTES, &key_pair));

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, MLKEM768_SHAREDSECRETBYTES));
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

  uint8_t publicKey[MLKEM768_PUBLICKEYBYTES];
  uint8_t secretKey[MLKEM768_SECRETKEYBYTES];

  Mlkem768_GenerateKeyPair(publicKey, secretKey, key_generation_seed.data());

  MlKem768_KeyPairUnpacked key_pair;
  ASSERT_TRUE(Mlkem768_GenerateKeyPairUnpacked_FromSeed(
      &key_pair, key_generation_seed.data(),
      MLKEM768_KEY_GENERATION_RANDOMNESS));

  // Serialize the PK to compare with the other one.
  CBB serialized_pk;
  CBB_init(&serialized_pk, MLKEM768_PUBLICKEYBYTES);
  MlKem768_PublicKeyUnpacked unpacked_pk;
  MlKem768_PublicKey(&unpacked_pk, &key_pair);
  ASSERT_TRUE(Mlkem768_MarshalPublicKey(&serialized_pk, &unpacked_pk));
  uint8_t *serialized_public_key;
  size_t encoded_len;
  CBB_finish(&serialized_pk, &serialized_public_key, &encoded_len);

  ASSERT_EQ((size_t)MLKEM768_PUBLICKEYBYTES, encoded_len);
  ASSERT_EQ(0, memcmp(serialized_public_key, publicKey, encoded_len));

  OPENSSL_free(serialized_public_key);

  uint8_t pk_hash[32];
  BORINGSSL_keccak(pk_hash, sizeof(pk_hash), publicKey, sizeof(publicKey),
                   boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(pk_hash, sha3_256_hash_of_public_key.data(), 32));

  uint8_t sk_hash[32];
  BORINGSSL_keccak(sk_hash, sizeof(sk_hash), secretKey, sizeof(secretKey),
                   boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(sk_hash, sha3_256_hash_of_secret_key.data(), 32));

  uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];
  Mlkem768_Encapsulate(ciphertext, sharedSecret, &publicKey,
                       encapsulation_seed.data());
  uint8_t ct_hash[32];
  BORINGSSL_keccak(ct_hash, sizeof(ct_hash), ciphertext, sizeof(ciphertext),
                   boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(ct_hash, sha3_256_hash_of_ciphertext.data(), 32));
  EXPECT_EQ(0, memcmp(sharedSecret, shared_secret.data(),
                      MLKEM768_SHAREDSECRETBYTES));

  // Unpacked encaps
  uint8_t UnpackedCiphertext[MLKEM768_CIPHERTEXTBYTES] = {0};
  uint8_t UnpackedSharedSecret[MLKEM768_SHAREDSECRETBYTES] = {0};

  CBS encoded_public_key_cbs;
  CBS_init(&encoded_public_key_cbs, publicKey, sizeof(publicKey));
  MlKem768_PublicKeyUnpacked unpacked_public_key;
  ASSERT_TRUE(
      Mlkem768_ParsePublicKey(&unpacked_public_key, &encoded_public_key_cbs));

  MlKem768_Encapsulate_ExternalEntropy(UnpackedCiphertext, UnpackedSharedSecret,
                                       &unpacked_public_key,
                                       encapsulation_seed.data());

  BORINGSSL_keccak(ct_hash, sizeof(ct_hash), UnpackedCiphertext,
                   sizeof(UnpackedCiphertext), boringssl_sha3_256);
  EXPECT_EQ(0, memcmp(ct_hash, sha3_256_hash_of_ciphertext.data(), 32));
  EXPECT_EQ(0, memcmp(UnpackedSharedSecret, shared_secret.data(),
                      MLKEM768_SHAREDSECRETBYTES));

  uint8_t sharedSecret2[MLKEM768_SHAREDSECRETBYTES];
  ctwrap_decaps(sharedSecret2, ciphertext, secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, MLKEM768_SHAREDSECRETBYTES));

  uint8_t sharedSecret3[MLKEM768_SHAREDSECRETBYTES];
  ASSERT_TRUE(MlKem768_Decapsulate(sharedSecret3, UnpackedCiphertext,
                                   MLKEM768_CIPHERTEXTBYTES, &key_pair));

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret3, MLKEM768_SHAREDSECRETBYTES));
}

TEST(MLKEM768TestKats, TestVectors) {
  FileTestGTest("crypto/libcrux-mlkem/mlkem768_kats.txt", MlkemKatFileTest);
}

// static void MlkemWycheproofKeygenFileTest(FileTest *t) {
//   bytes entropy, expected_public_key, expected_private_key;

//   t->IgnoreAttribute("comment");
//   ASSERT_TRUE(t->GetBytes(&entropy, "entropy"));
//   ASSERT_TRUE(t->GetBytes(&expected_public_key, "expected_public_key"));
//   ASSERT_TRUE(t->GetBytes(&expected_private_key, "expected_private_key"));

//   uint8_t publicKey[MLKEM768_PUBLICKEYBYTES];
//   uint8_t secretKey[MLKEM768_SECRETKEYBYTES];

//   Mlkem768_GenerateKeyPair(publicKey, secretKey, entropy.data());

//   EXPECT_EQ(0, memcmp(publicKey, expected_public_key.data(),
//                       MLKEM768_PUBLICKEYBYTES));
//   EXPECT_EQ(0, memcmp(secretKey, expected_private_key.data(),
//                       MLKEM768_SECRETKEYBYTES));
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

//   uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
//   uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];
//   auto ret = Mlkem768_Encapsulate(
//       ciphertext, sharedSecret,
//       reinterpret_cast<uint8_t(*)[MLKEM768_PUBLICKEYBYTES]>(public_key.data()),
//       entropy.data());

//   if (expected_result.compare("pass") == 0) {
//     EXPECT_EQ(1, ret);
//     EXPECT_EQ(0, memcmp(ciphertext, expected_ciphertext.data(),
//                         MLKEM768_CIPHERTEXTBYTES));
//     EXPECT_EQ(0, memcmp(sharedSecret, expected_shared_secret.data(),
//                         MLKEM768_SHAREDSECRETBYTES));
//   } else {
//     EXPECT_TRUE(ret == 0 || public_key.size() != MLKEM768_PUBLICKEYBYTES);
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
//     uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];
//     ctwrap_decaps(sharedSecret, ciphertext.data(), private_key.data());

//     EXPECT_EQ(0, memcmp(sharedSecret, expected_shared_secret.data(),
//                         MLKEM768_SHAREDSECRETBYTES));
//   } else {
//     // We don't check private keys.
//   }
// }

// // TEST(MLKEM768WycheproofDecaps, TestVectors) {
// //   FileTestGTest("crypto/mlkem/decaps768_wycheproof.txt",
// //                 MlkemWycheproofDecapsFileTest);
// // }
