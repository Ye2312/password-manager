#include "gtest/gtest.h"
#include "../include/password_manager.h"
#include <string>
#include <stdexcept>
#include <fstream>

class PasswordManagerTestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        remove("passwords.db");
        pm.initialize("test123");
    }

    void TearDown() override {
        remove("passwords.db");
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

TEST_F(PasswordManagerTestFixture, SaveLoad) {
    PasswordEntry entry{"save_test", "user", "pass", "note"};
    pm.add_entry(entry);
    pm.save_entries();

    PasswordManager new_pm;
    new_pm.initialize("test123");
    auto found = new_pm.find_entries("save_test");
    ASSERT_EQ(found.size(), 1);
    EXPECT_EQ(found[0].service, "save_test");
}

TEST_F(PasswordManagerTestFixture, VerifyMasterPassword) {
    EXPECT_TRUE(pm.verify_master_password("test123"));
    EXPECT_FALSE(pm.verify_master_password("wrongpass"));
}

TEST_F(PasswordManagerTestFixture, EdgeCases) {
    PasswordEntry long_entry{
        std::string(100, 'a'), // Очень длинный сервис
        "user",
        std::string(100, 'b'), // Очень длинный пароль
        ""
    };
    EXPECT_NO_THROW(pm.add_entry(long_entry));

    auto found = pm.find_entries(std::string(100, 'a'));
    EXPECT_EQ(found.size(), 1);
}