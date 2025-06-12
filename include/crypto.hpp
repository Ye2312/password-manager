#pragma once
#include <string>
#include <vector>

class Crypto {
public:
    static std::vector<unsigned char> encrypt(const std::string& plaintext, const std::string& key);

    static std::string decrypt(const std::vector<unsigned char>& ciphertext, const std::string& key);
};