#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdexcept>
#include <vector>

using namespace std;

vector<unsigned char> Crypto::generate_random_bytes(size_t length) {
    vector<unsigned char> buffer(length);
    if (RAND_bytes(buffer.data(), length) != 1) {
        throw CryptoException("Failed to generate random bytes");
    }
    return buffer;
}

string Crypto::encrypt(const string& plaintext, const string& key, const string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoException("Failed to create cipher context");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                          reinterpret_cast<const unsigned char*>(key.data()),
                          reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Encryption initialization failed");
    }

    int max_ciphertext_len = plaintext.size() + EVP_MAX_BLOCK_LENGTH;
    vector<unsigned char> ciphertext(max_ciphertext_len);
    int len, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                         reinterpret_cast<const unsigned char*>(plaintext.data()),
                         plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Encryption update failed");
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Encryption finalization failed");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

string Crypto::decrypt(const string& ciphertext, const string& key, const string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoException("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                          reinterpret_cast<const unsigned char*>(key.data()),
                          reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Decryption initialization failed");
    }

    int max_plaintext_len = ciphertext.size() + EVP_MAX_BLOCK_LENGTH;
    vector<unsigned char> plaintext(max_plaintext_len);
    int len, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         reinterpret_cast<const unsigned char*>(ciphertext.data()),
                         ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Decryption update failed");
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Decryption finalization failed");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return string(plaintext.begin(), plaintext.begin() + plaintext_len);
}