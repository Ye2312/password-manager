#include "password_manager.h"
#include "crypto.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <cstdlib>
#include <openssl/evp.h>
using namespace std;

static string vector_to_string(const vector<unsigned char>& vec) {
    return string(vec.begin(), vec.end());
}

static string generate_iv() {
    vector<unsigned char> iv = Crypto::generate_random_bytes(16);
    return vector_to_string(iv);
}

void PasswordManager::initialize(const string& master_password, const string& storage_path) {
    master_key_ = derive_key(master_password);
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
        if (entry.service.find(query) != string::npos || 
            entry.username.find(query) != string::npos) {
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

    string chars = lower;
    if (use_upper) chars += upper;
    if (use_digits) chars += digits;
    if (use_special) chars += special;

    string result;
    int actual_length = (length > 0) ? length : gen_settings_.length;
    for (int i = 0; i < actual_length; ++i) {
        result += chars[rand() % chars.size()];
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
    string full_data = iv + encrypted_data; // IV + зашифрованные данные

    ofstream file(storage_path_, ios::binary);
    if (!file) {
        throw runtime_error("Failed to save entries");
    }
    file.write(full_data.data(), full_data.size());
    file.close(); // Явное закрытие файла
}

void PasswordManager::load_entries() {
    ifstream file(storage_path_, ios::binary);
    if (!file) return; // Игнорируем, если файла нет

    // Читаем весь файл в буфер
    string encrypted_data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close(); // Явное закрытие файла
    if (encrypted_data.size() <= 16) return; // IV занимает 16 байт

    try {
        string iv = encrypted_data.substr(0, 16);
        string actual_data = encrypted_data.substr(16);
        string json_data = Crypto::decrypt(actual_data, master_key_, iv);
        // TODO: JSON parsing
        entries_.clear(); // Очищаем перед загрузкой
        // Здесь должен быть парсинг JSON, но пока оставляем пустым
    } catch (const exception& e) {
        throw runtime_error("Failed to load entries: " + string(e.what()));
    }
}


string PasswordManager::derive_key(const string& password) const {
    const unsigned char* salt = Crypto::generate_random_bytes(16).data();
    unsigned char key[32]; // 256 бит
    int iterations = 10000;

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                         salt, 16,
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