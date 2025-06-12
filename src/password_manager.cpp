#include "password_manager.h"
#include "crypto.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <cstdlib>

using namespace std;

// Вспомогательная функция для конвертации vector<unsigned char> в string
static string vector_to_string(const vector<unsigned char>& vec) {
    return string(vec.begin(), vec.end());
}

// Вспомогательная функция для генерации IV
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
    entries_.push_back(entry);
    save_entries();
}

vector<PasswordEntry> PasswordManager::find_entries(const string& service) const {
    if (service.empty()) {
        return entries_;
    }

    vector<PasswordEntry> result;
    copy_if(entries_.begin(), entries_.end(), back_inserter(result),
        [&service](const PasswordEntry& entry) {
            return entry.service.find(service) != string::npos;
        });
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
    for (int i = 0; i < length; ++i) {
        result += chars[rand() % chars.size()];
    }
    return result;
}

// Приватные методы
void PasswordManager::load_entries() {
    ifstream file(storage_path_, ios::binary);
    if (!file) return;

    string encrypted_data(istreambuf_iterator<char>(file), {});
    if (encrypted_data.size() <= 16) return; // IV + минимум 1 байт данных

    try {
        string iv = encrypted_data.substr(0, 16);
        string actual_data = encrypted_data.substr(16);
        string json_data = Crypto::decrypt(actual_data, master_key_, iv);
        // TODO: Реализовать парсинг JSON
    } catch (const exception& e) {
        throw runtime_error("Failed to decrypt data: " + string(e.what()));
    }
}

void PasswordManager::save_entries() const {
    // TODO: Реализовать сериализацию в JSON
    string json_data = "[]"; // Заглушка
    
    string iv = generate_iv();
    string encrypted_data = Crypto::encrypt(json_data, master_key_, iv);
    encrypted_data = iv + encrypted_data; // Сохраняем IV вместе с данными

    ofstream file(storage_path_, ios::binary);
    if (!file) {
        throw runtime_error("Failed to open file for writing");
    }
    file << encrypted_data;
}

string PasswordManager::derive_key(const string& password) const {
    vector<unsigned char> bytes = Crypto::generate_random_bytes(32);
    return vector_to_string(bytes);
}