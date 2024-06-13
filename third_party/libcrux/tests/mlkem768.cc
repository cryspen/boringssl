#include <gtest/gtest.h>
#include <fstream>
#include <nlohmann/json.hpp>

#include "Libcrux_Kem_ML_KEM768.h"

using namespace std;

typedef vector<uint8_t> bytes;

TEST(MLKEM768Test, ConsistencyTest) {
  uint8_t randomness[64] = {0x37};
  uint8_t publicKey[MLKEM768_PUBLICKEYBYTES];
  uint8_t secretKey[MLKEM768_SECRETKEYBYTES];

  Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey, randomness);

  uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
  uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];

  uint8_t encap_randomness[64] = {0x38};
  Libcrux_Kyber768_Encapsulate(ciphertext, sharedSecret, &publicKey,
                               encap_randomness);

  uint8_t sharedSecret2[MLKEM768_SHAREDSECRETBYTES];
  Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

  EXPECT_EQ(0, memcmp(sharedSecret, sharedSecret2, MLKEM768_SHAREDSECRETBYTES));
}


vector<uint8_t> from_hex(const string &hex) {
  if (hex.length() % 2 == 1) {
    throw invalid_argument("Odd-length hex string");
  }

  int len = static_cast<int>(hex.length()) / 2;
  vector<uint8_t> out(len);
  for (int i = 0; i < len; i += 1) {
    string byte = hex.substr(2 * i, 2);
    out[i] = static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16));
  }

  return out;
}

string bytes_to_hex(const vector<uint8_t> &data) {
  stringstream hex(ios_base::out);
  hex.flags(ios::hex);
  for (const auto &byte : data) {
    hex << setw(2) << setfill('0') << int(byte);
  }
  return hex.str();
}

class KAT {
 public:
  bytes key_generation_seed;
  bytes sha3_256_hash_of_public_key;
  bytes sha3_256_hash_of_secret_key;
  bytes encapsulation_seed;
  bytes sha3_256_hash_of_ciphertext;
  bytes shared_secret;
};

vector<KAT> read_kats(string path) {
  ifstream kat_file(path);
  nlohmann::json kats_raw;
  kat_file >> kats_raw;

  vector<KAT> kats;

  // Read test group
  for (auto &kat_raw : kats_raw.items()) {
    auto kat_raw_value = kat_raw.value();

    kats.push_back(KAT{
        .key_generation_seed = from_hex(kat_raw_value["key_generation_seed"]),
        .sha3_256_hash_of_public_key =
            from_hex(kat_raw_value["sha3_256_hash_of_public_key"]),
        .sha3_256_hash_of_secret_key =
            from_hex(kat_raw_value["sha3_256_hash_of_secret_key"]),
        .encapsulation_seed = from_hex(kat_raw_value["encapsulation_seed"]),
        .sha3_256_hash_of_ciphertext =
            from_hex(kat_raw_value["sha3_256_hash_of_ciphertext"]),
        .shared_secret = from_hex(kat_raw_value["shared_secret"]),
    });
  }

  return kats;
}

TEST(MlKem768TestPortable, NISTKnownAnswerTest) {
  // This should be done in a portable way.
  auto kats = read_kats("tests/mlkem768_nistkats.json");

  for (auto kat : kats) {
    uint8_t publicKey[MLKEM768_PUBLICKEYBYTES];
    uint8_t secretKey[MLKEM768_SECRETKEYBYTES];

    Libcrux_Kyber768_GenerateKeyPair(publicKey, secretKey,
                                     kat.key_generation_seed.data());

    uint8_t pk_hash[32];
    Libcrux_Sha3_256(publicKey, MLKEM768_PUBLICKEYBYTES, &pk_hash);
    EXPECT_EQ(0, memcmp(pk_hash, kat.sha3_256_hash_of_public_key.data(), 32));

    uint8_t sk_hash[32];
    Libcrux_Sha3_256(secretKey, MLKEM768_SECRETKEYBYTES, &sk_hash);
    EXPECT_EQ(0, memcmp(sk_hash, kat.sha3_256_hash_of_secret_key.data(), 32));

    uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
    uint8_t sharedSecret[MLKEM768_SHAREDSECRETBYTES];
    Libcrux_Kyber768_Encapsulate(ciphertext, sharedSecret, &publicKey,
                                 kat.encapsulation_seed.data());
    uint8_t ct_hash[32];
    Libcrux_Sha3_256(ciphertext, MLKEM768_CIPHERTEXTBYTES, &ct_hash);
    EXPECT_EQ(0, memcmp(ct_hash, kat.sha3_256_hash_of_ciphertext.data(), 32));
    EXPECT_EQ(0, memcmp(sharedSecret, kat.shared_secret.data(),
                        MLKEM768_SHAREDSECRETBYTES));

    uint8_t sharedSecret2[MLKEM768_SHAREDSECRETBYTES];
    Libcrux_Kyber768_Decapsulate(sharedSecret2, &ciphertext, &secretKey);

    EXPECT_EQ(0,
              memcmp(sharedSecret, sharedSecret2, MLKEM768_SHAREDSECRETBYTES));
  }
}
