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

struct PasswordGeneratorSettings {
    bool use_upper = true;
    bool use_digits = true;
    bool use_special = true;
    int length = 16;
};

class PasswordManager {
public:
    void initialize(const std::string& master_password, 
                  const std::string& storage_path = "passwords.db");

    void add_entry(const PasswordEntry& entry);
    void edit_entry(size_t index, const PasswordEntry& new_entry);
    void delete_entry(size_t index);
    void set_generator_settings(bool use_upper, bool use_digits, bool use_special, int length = 16);
    
    std::vector<PasswordEntry> find_entries(const std::string& query) const;
    std::string generate_password(int length = -1, 
                                bool use_upper = true, 
                                bool use_digits = true, 
                                bool use_special = true) const;

private:
    std::string master_key_;
    std::string storage_path_;
    std::vector<PasswordEntry> entries_;
    PasswordGeneratorSettings gen_settings_;

    void load_entries();
    void save_entries() const;
    std::string derive_key(const std::string& password) const;
    void clear_sensitive_data(std::string& data) const;
};