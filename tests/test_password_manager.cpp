#include "gtest/gtest.h"
#include "../include/password_manager.h"
#include <string>
#include <stdexcept>
#include <fstream>

class PasswordManagerTestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        // Удаляем файл перед каждым тестом
        remove("passwords.db");
        pm.initialize("test123");
    }

    PasswordManager pm;
};

TEST_F(PasswordManagerTestFixture, AddFindDelete) {
    PasswordEntry entry{"test", "user", "pass", ""};
    pm.add_entry(entry);
    auto found = pm.find_entries("test");
    ASSERT_EQ(found.size(), 1);

    PasswordEntry new_entry{"test", "new_user", "new_pass", "notes"};
    pm.edit_entry(0, new_entry);
    found = pm.find_entries("test");
    EXPECT_EQ(found[0].username, "new_user");

    pm.delete_entry(0);
    found = pm.find_entries("test");
    EXPECT_TRUE(found.empty());
}

TEST_F(PasswordManagerTestFixture, PasswordGeneration) {
    std::string pass1 = pm.generate_password();
    EXPECT_EQ(pass1.length(), 16);

    pm.set_generator_settings(true, false, false, 10);
    std::string pass2 = pm.generate_password();
    EXPECT_EQ(pass2.length(), 10);

    std::string pass3 = pm.generate_password(12, false, true, false);
    EXPECT_EQ(pass3.length(), 12);
}

TEST_F(PasswordManagerTestFixture, ErrorHandling) {
    PasswordEntry empty_entry;
    EXPECT_THROW(pm.add_entry(empty_entry), std::invalid_argument);

    PasswordEntry valid_entry{"test", "user", "pass", ""};
    pm.add_entry(valid_entry);

    PasswordEntry new_entry{"test", "new_user", "new_pass", ""};
    EXPECT_THROW(pm.edit_entry(1, new_entry), std::out_of_range);

    EXPECT_THROW(pm.delete_entry(1), std::out_of_range);
}