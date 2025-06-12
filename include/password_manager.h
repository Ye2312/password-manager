#pragma once
#include <string>
#include <vector>
#include <map>

struct PasswordEntry {
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
};

class PasswordManager {
public:
    /**
     * @brief Инициализирует хранилище с мастер-паролем
     * @param master_password Мастер-пароль
     * @param storage_path Путь к файлу хранилища
     */
    void initialize(const std::string& master_password, 
                  const std::string& storage_path = "passwords.db");

    /**
     * @brief Добавляет новую запись в хранилище
     */
    void add_entry(const PasswordEntry& entry);

    /**
     * @brief Ищет записи по сервису
     */
    std::vector<PasswordEntry> find_entries(const std::string& service) const;

    /**
     * @brief Генерирует безопасный пароль
     */
    std::string generate_password(int length = 16, 
                                bool use_upper = true, 
                                bool use_digits = true, 
                                bool use_special = true) const;

private:
    std::string master_key_;
    std::string storage_path_;
    std::vector<PasswordEntry> entries_;

    void load_entries();
    void save_entries() const;
    std::string derive_key(const std::string& password) const;
};