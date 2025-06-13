#include "password_manager.h"
#include "crypto.h"
#include <iostream>
#include <string>
#include <termios.h>
#include <unistd.h>

using namespace std;

string get_hidden_input(const string& prompt) {
    cout << prompt;
    termios old_settings, new_settings;
    tcgetattr(STDIN_FILENO, &old_settings);
    new_settings = old_settings;
    new_settings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    
    string input;
    getline(cin, input);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    cout << "\n";
    return input;
}

void print_entries(const vector<PasswordEntry>& entries) {
    for (size_t i = 0; i < entries.size(); ++i) {
        cout << i << ". Service: " << entries[i].service 
             << "\n   Username: " << entries[i].username << "\n";
    }
}

void print_menu() {
    cout << "\n🔐 Password Manager 🔐\n"
         << "1. Add entry\n"
         << "2. Find entries\n"
         << "3. Generate password\n"
         << "4. Edit entry\n"
         << "5. Delete entry\n"
         << "6. Password generator settings\n"
         << "7. List all entries\n"
         << "8. Exit\n"
         << "> ";
}

PasswordEntry input_password_entry(bool generate_password) {
    PasswordEntry entry;
    cout << "Service: ";
    getline(cin, entry.service);
    cout << "Username: ";
    getline(cin, entry.username);
    
    if (generate_password) {
        entry.password = PasswordManager().generate_password();
        cout << "Generated password: " << entry.password << "\n";
    } else {
        cout << "Password (leave empty to generate): ";
        entry.password = get_hidden_input("");
        if (entry.password.empty()) {
            entry.password = PasswordManager().generate_password();
            cout << "Generated password: " << entry.password << "\n";
        }
    }
    
    cout << "Notes: ";
    getline(cin, entry.notes);
    return entry;
}

int main() {
    PasswordManager manager;
    
    try {
        string master_password = get_hidden_input("Enter master password: ");
        manager.initialize(master_password);
        
        int choice = 0;
        while (choice != 8) {
            print_menu();
            cin >> choice;
            cin.ignore();
            
            try {
                switch (choice) {
                    case 1: {
                        PasswordEntry entry = input_password_entry(false);
                        manager.add_entry(entry);
                        cout << "✅ Entry added!\n";
                        break;
                    }
                    case 2: {
                        cout << "Search query: ";
                        string query;
                        getline(cin, query);
                        auto entries = manager.find_entries(query);
                        print_entries(entries);
                        break;
                    }
                    case 3: {
                        cout << "Password length: ";
                        int length;
                        cin >> length;
                        string password = manager.generate_password(length);
                        cout << "🔑 Generated: " << password << "\n";
                        break;
                    }
                    case 4: {
                        auto entries = manager.find_entries("");
                        print_entries(entries);
                        cout << "Enter index to edit: ";
                        size_t index;
                        cin >> index;
                        cin.ignore();
                        PasswordEntry new_entry = input_password_entry(false);
                        manager.edit_entry(index, new_entry);
                        cout << "✅ Entry updated!\n";
                        break;
                    }
                    case 5: {
                        auto entries = manager.find_entries("");
                        print_entries(entries);
                        cout << "Enter index to delete: ";
                        size_t index;
                        cin >> index;
                        manager.delete_entry(index);
                        cout << "✅ Entry deleted!\n";
                        break;
                    }
                    case 6: {
                        cout << "Password length [8-32]: ";
                        int length;
                        cin >> length;
                        cout << "Use uppercase? (1/0): ";
                        bool upper;
                        cin >> upper;
                        cout << "Use digits? (1/0): ";
                        bool digits;
                        cin >> digits;
                        cout << "Use special chars? (1/0): ";
                        bool special;
                        cin >> special;
                        manager.set_generator_settings(upper, digits, special, length);
                        break;
                    }
                    case 7: {
                        auto entries = manager.find_entries("");
                        print_entries(entries);
                        break;
                    }
                    case 8: {
                        cout << "Goodbye!\n";
                        break;
                    }
                    default:
                        cout << "Invalid choice!\n";
                }
            } catch (const exception& e) {
                cerr << "❌ Error: " << e.what() << "\n";
            }
        }
    } catch (const exception& e) {
        cerr << "❌ Critical error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}