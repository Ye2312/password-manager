#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>

/**
 * @brief Exception class for cryptographic errors.
 */
class CryptoException {
public:
    /**
     * @brief Constructs a CryptoException with a message.
     * @param message The error message.
     */
    explicit CryptoException(const std::string& message) : message_(message) {}
    /**
     * @brief Returns the error message.
     * @return The error message.
     */
    std::string what() const { return message_; }

private:
    std::string message_; /**< The stored error message. */
};

/**
 * @brief Provides cryptographic functions using AES-256-CBC encryption.
 * This class handles encryption, decryption, and random byte generation.
 */
class Crypto {
public:
    /**
     * @brief Generates a vector of random bytes.
     * @param length The number of bytes to generate.
     * @return A vector of random bytes.
     * @throw CryptoException if random generation fails.
     */
    static std::vector<unsigned char> generate_random_bytes(size_t length);

    /**
     * @brief Encrypts plaintext using AES-256-CBC.
     * @param plaintext The text to encrypt.
     * @param key The encryption key (must be 32 bytes).
     * @param iv The initialization vector (must be 16 bytes).
     * @return The encrypted ciphertext.
     * @throw std::invalid_argument if input parameters are invalid.
     * @throw CryptoException if encryption fails.
     */
    static std::string encrypt(const std::string& plaintext, const std::string& key, const std::string& iv);

    /**
     * @brief Decrypts ciphertext using AES-256-CBC.
     * @param ciphertext The text to decrypt.
     * @param key The decryption key (must be 32 bytes).
     * @param iv The initialization vector (must be 16 bytes).
     * @return The decrypted plaintext.
     * @throw std::invalid_argument if input parameters are invalid.
     * @throw CryptoException if decryption fails.
     */
    static std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv);
};

#endif