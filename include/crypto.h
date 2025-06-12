#pragma once
#include <string>
#include <vector>

class CryptoException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Crypto {
public:
    /**
     * @brief Шифрует данные с использованием AES-256-CBC
     * @param plaintext Исходные данные для шифрования
     * @param key Ключ шифрования (должен быть 32 байта)
     * @param iv Вектор инициализации (должен быть 16 байт)
     * @return Зашифрованные данные в формате base64
     * @throws CryptoException В случае ошибки шифрования
     */
    static std::string encrypt(const std::string& plaintext, 
                             const std::string& key, 
                             const std::string& iv);

    /**
     * @brief Дешифрует данные
     * @param ciphertext Зашифрованные данные в base64
     * @param key Ключ шифрования (32 байта)
     * @param iv Вектор инициализации (16 байт)
     * @return Расшифрованные данные
     * @throws CryptoException В случае ошибки дешифрования
     */
    static std::string decrypt(const std::string& ciphertext, 
                             const std::string& key, 
                             const std::string& iv);

    /**
     * @brief Генерирует случайные байты
     * @param length Количество байт для генерации
     * @return Вектор случайных байт
     */
    static std::vector<unsigned char> generate_random_bytes(size_t length);
};