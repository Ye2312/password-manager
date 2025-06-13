#include "gtest/gtest.h"
#include "../include/crypto.h"
#include <vector>

TEST(CryptoTest, EncryptDecrypt) {
    std::vector<unsigned char> key_vec = Crypto::generate_random_bytes(32);
    std::vector<unsigned char> iv_vec = Crypto::generate_random_bytes(16);
    std::string key(key_vec.begin(), key_vec.end());
    std::string iv(iv_vec.begin(), iv_vec.end());
    
    std::string plaintext = "TestData";
    std::string ciphertext = Crypto::encrypt(plaintext, key, iv);
    std::string decrypted = Crypto::decrypt(ciphertext, key, iv);
    
    EXPECT_EQ(plaintext, decrypted);
}

TEST(CryptoTest, RandomBytes) {
    auto bytes1 = Crypto::generate_random_bytes(32);
    auto bytes2 = Crypto::generate_random_bytes(32);
    
    EXPECT_EQ(bytes1.size(), 32);
    EXPECT_NE(bytes1, bytes2);
}

TEST(CryptoTest, ErrorHandling) {
    std::string key(32, 'a');
    std::string iv(16, 'b');
    
    EXPECT_THROW(Crypto::encrypt("", key, iv), std::invalid_argument); // Пустой текст
    EXPECT_THROW(Crypto::decrypt("", key, iv), std::invalid_argument); // Пустой шифротекст
    EXPECT_THROW(Crypto::encrypt("test", std::string(16, 'a'), iv), std::invalid_argument); // Короткий ключ
}