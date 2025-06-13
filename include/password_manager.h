#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <string>
#include <vector>

/**
 * @brief Structure representing a password entry.
 */
struct PasswordEntry {
    std::string service;  /**< The service name (e.g., "gmail"). */
    std::string username; /**< The username for the service. */
    std::string password; /**< The encrypted password. */
    std::string notes;    /**< Additional notes for the entry. */
};

/**
 * @brief Structure for password generator settings.
 */
struct PasswordGeneratorSettings {
    bool use_upper = true;   /**< Whether to include uppercase letters. */
    bool use_digits = true;  /**< Whether to include digits. */
    bool use_special = true; /**< Whether to include special characters. */
    int length = 16;         /**< The length of the generated password. */
};

/**
 * @brief Manages password entries with AES-256-CBC encryption.
 * This class provides functionality to add, edit, delete, and search password entries,
 * as well as generate passwords and manage storage.
 */
class PasswordManager {
public:
    /**
     * @brief Initializes the password manager with a master password.
     * @param master_password The master password for encryption.
     * @param storage_path The path to the storage file (default: "passwords.db").
     */
    void initialize(const std::string& master_password, const std::string& storage_path = "passwords.db");

    /**
     * @brief Adds a new password entry.
     * @param entry The password entry to add.
     * @throw std::invalid_argument if service or username is empty.
     */
    void add_entry(const PasswordEntry& entry);

    /**
     * @brief Edits an existing password entry.
     * @param index The index of the entry to edit.
     * @param new_entry The new entry data.
     * @throw std::out_of_range if index is invalid.
     * @throw std::invalid_argument if service or username is empty.
     */
    void edit_entry(size_t index, const PasswordEntry& new_entry);

    /**
     * @brief Deletes a password entry.
     * @param index The index of the entry to delete.
     * @throw std::out_of_range if index is invalid.
     */
    void delete_entry(size_t index);

    /**
     * @brief Sets password generator settings.
     * @param use_upper Whether to include uppercase letters.
     * @param use_digits Whether to include digits.
     * @param use_special Whether to include special characters.
     * @param length The length of the generated password (min 8, max 32).
     */
    void set_generator_settings(bool use_upper, bool use_digits, bool use_special, int length = 16);

    /**
     * @brief Finds entries matching a query.
     * @param query The search query.
     * @return A vector of matching password entries.
     */
    std::vector<PasswordEntry> find_entries(const std::string& query) const;

    /**
     * @brief Generates a random password.
     * @param length The desired length (if negative, uses default settings).
     * @param use_upper Whether to include uppercase letters.
     * @param use_digits Whether to include digits.
     * @param use_special Whether to include special characters.
     * @return The generated password.
     * @throw std::invalid_argument if no character sets are selected.
     */
    std::string generate_password(int length = -1, bool use_upper = true, bool use_digits = true, bool use_special = true) const;

    /**
     * @brief Returns whether uppercase letters are used in password generation.
     * @return True if uppercase letters are used, false otherwise.
     */
    bool get_use_upper() const { return gen_settings_.use_upper; }

    /**
     * @brief Returns whether digits are used in password generation.
     * @return True if digits are used, false otherwise.
     */
    bool get_use_digits() const { return gen_settings_.use_digits; }

    /**
     * @brief Returns whether special characters are used in password generation.
     * @return True if special characters are used, false otherwise.
     */
    bool get_use_special() const { return gen_settings_.use_special; }

    /**
     * @brief Returns the length of generated passwords.
     * @return The length of the generated password.
     */
    int get_length() const { return gen_settings_.length; }

    /**
     * @brief Verifies the master password.
     * @param password The password to verify.
     * @return True if the password matches, false otherwise.
     */
    bool verify_master_password(const std::string& password) const { return derive_key(password) == master_key_; }

    /**
     * @brief Saves all password entries to the storage file.
     */
    void save_entries() const;

private:
    std::string master_key_;          /**< The derived master key for encryption. */
    std::string storage_path_;        /**< The path to the storage file. */
    std::vector<unsigned char> salt_; /**< The salt for key derivation. */
    std::vector<PasswordEntry> entries_; /**< The list of password entries. */
    PasswordGeneratorSettings gen_settings_; /**< The current generator settings. */

    /**
     * @brief Loads password entries from the storage file.
     */
    void load_entries();

    /**
     * @brief Derives a key from a password using PBKDF2.
     * @param password The password to derive the key from.
     * @return The derived key (32 bytes).
     * @throw std::runtime_error if key derivation fails.
     */
    std::string derive_key(const std::string& password) const;

    /**
     * @brief Clears sensitive data from a string.
     * @param data The string to clear.
     */
    void clear_sensitive_data(std::string& data) const;
};

#endif