#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>

class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& message) : std::runtime_error(message) {}
};

class Crypto {
public:
    static std::vector<unsigned char> generate_random_bytes(size_t length);
    static std::string encrypt(const std::string& plaintext, const std::string& key, const std::string& iv);
    static std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv);
};

#endif