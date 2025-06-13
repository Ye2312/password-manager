#include "password_manager.h"
#include "crypto.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
using namespace std;
using json = nlohmann::json;

static string vector_to_string(const vector<unsigned char>& vec) {
    return string(vec.begin(), vec.end());
}

static string generate_iv() {
    vector<unsigned char> iv = Crypto::generate_random_bytes(16);
    return vector_to_string(iv);
}

void PasswordManager::initialize(const string& master_password, const string& storage_path) {
    ifstream file(storage_path, ios::binary);
    if (file.is_open()) {
        string data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();
        if (data.size() >= 32) { // salt (16) + IV (16)
            salt_ = vector<unsigned char>(data.begin(), data.begin() + 16); // Восстанавливаем salt
            master_key_ = derive_key(master_password); // Используем восстановленный salt
        } else {
            salt_ = Crypto::generate_random_bytes(16); // Новый salt, если файла нет
            master_key_ = derive_key(master_password);
        }
    } else {
        salt_ = Crypto::generate_random_bytes(16); // Новый salt, если файла нет
        master_key_ = derive_key(master_password);
    }
    storage_path_ = storage_path;
    load_entries();
}

void PasswordManager::add_entry(const PasswordEntry& entry) {
    if (entry.service.empty() || entry.username.empty()) {
        throw invalid_argument("Service and username cannot be empty");
    }
    entries_.push_back(entry);
    save_entries();
}

void PasswordManager::edit_entry(size_t index, const PasswordEntry& new_entry) {
    if (index >= entries_.size()) throw out_of_range("Invalid index");
    if (new_entry.service.empty() || new_entry.username.empty()) {
        throw invalid_argument("Service and username cannot be empty");
    }
    entries_[index] = new_entry;
    save_entries();
}

void PasswordManager::delete_entry(size_t index) {
    if (index >= entries_.size()) throw out_of_range("Invalid index");
    entries_.erase(entries_.begin() + index);
    save_entries();
}

void PasswordManager::set_generator_settings(bool use_upper, bool use_digits, bool use_special, int length) {
    gen_settings_ = {use_upper, use_digits, use_special, max(8, min(32, length))};
}

vector<PasswordEntry> PasswordManager::find_entries(const string& query) const {
    vector<PasswordEntry> result;
    for (const auto& entry : entries_) {
        if (entry.service.find(query) != string::npos || entry.username.find(query) != string::npos) {
            result.push_back(entry);
        }
    }
    return result;
}

string PasswordManager::generate_password(int length, bool use_upper, bool use_digits, bool use_special) const {
    const string lower = "abcdefghijklmnopqrstuvwxyz";
    const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const string digits = "0123456789";
    const string special = "!@#$%^&*()";

    bool final_use_upper = (use_upper != true) ? use_upper : gen_settings_.use_upper;
    bool final_use_digits = (use_digits != true) ? use_digits : gen_settings_.use_digits;
    bool final_use_special = (use_special != true) ? use_special : gen_settings_.use_special;
    int final_length = (length > 0) ? length : gen_settings_.length;

    string chars = lower;
    if (final_use_upper) chars += upper;
    if (final_use_digits) chars += digits;
    if (final_use_special) chars += special;

    if (chars.empty()) {
        throw invalid_argument("No character sets selected for password generation");
    }

    string result;
    vector<unsigned char> random_bytes = Crypto::generate_random_bytes(final_length);
    for (int i = 0; i < final_length; ++i) {
        result += chars[random_bytes[i] % chars.size()];
    }
    return result;
}

void PasswordManager::save_entries() const {
    string json_data = "[";
    for (const auto& entry : entries_) {
        json_data += "{\"service\":\"" + entry.service + "\",\"username\":\"" + entry.username + 
                     "\",\"password\":\"" + entry.password + "\",\"notes\":\"" + entry.notes + "\"},";
    }
    if (!entries_.empty()) json_data.pop_back();
    json_data += "]";

    string iv = generate_iv();
    string encrypted_data = Crypto::encrypt(json_data, master_key_, iv);
    string full_data = vector_to_string(salt_) + iv + encrypted_data; // Сохраняем salt + IV + данные

    ofstream file(storage_path_, ios::binary);
    if (!file) {
        throw runtime_error("Failed to save entries");
    }
    file.write(full_data.data(), full_data.size());
    file.close();
}

void PasswordManager::load_entries() {
    ifstream file(storage_path_, ios::binary);
    if (!file) return;

    string data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();
    if (data.size() <= 32) return; // salt (16) + IV (16)

    try {
        salt_ = vector<unsigned char>(data.begin(), data.begin() + 16); // Восстанавливаем salt
        string iv = data.substr(16, 16); // Извлекаем IV
        string encrypted_data = data.substr(32); // Извлекаем зашифрованные данные
        string json_data = Crypto::decrypt(encrypted_data, master_key_, iv);

        entries_.clear();
        json j = json::parse(json_data);
        for (const auto& item : j) {
            PasswordEntry entry;
            entry.service = item["service"].get<string>();
            entry.username = item["username"].get<string>();
            entry.password = item["password"].get<string>();
            entry.notes = item["notes"].get<string>();
            entries_.push_back(entry);
        }
    } catch (const exception& e) {
        throw runtime_error("Failed to load entries: " + string(e.what()));
    }
}

string PasswordManager::derive_key(const string& password) const {
    unsigned char key[32];
    int iterations = 10000;

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                         salt_.data(), salt_.size(),
                         iterations,
                         EVP_sha256(),
                         32, key) != 1) {
        throw runtime_error("Key derivation failed");
    }
    return string(reinterpret_cast<char*>(key), 32);
}

void PasswordManager::clear_sensitive_data(string& data) const {
    fill(data.begin(), data.end(), '\0');
}