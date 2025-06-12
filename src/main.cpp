#include "password_manager.h"
#include "crypto.h"
#include <iostream>
#include <string>
#include <termios.h>
#include <unistd.h>

std::string get_password_input(const std::string& prompt) {
    std::cout << prompt;
    
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::string password;
    std::getline(std::cin, password);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    
    return password;
}

void show_menu() {
    std::cout << "\nPassword Manager Menu:\n"
              << "1. Add new entry\n"
              << "2. Find entries\n"
              << "3. Generate password\n"
              << "4. Exit\n"
              << "Choose option: ";
}

int main() {
    PasswordManager pm;
    
    try {
        std::string master_password = get_password_input("Enter master password: ");
        pm.initialize(master_password);
        
        int choice = 0;
        while (choice != 4) {
            show_menu();
            std::cin >> choice;
            std::cin.ignore();
            
            switch (choice) {
                case 1: {
                    PasswordEntry entry;
                    std::cout << "Service: "; std::getline(std::cin, entry.service);
                    std::cout << "Username: "; std::getline(std::cin, entry.username);
                    entry.password = get_password_input("Password (leave empty to generate): ");
                    
                    if (entry.password.empty()) {
                        entry.password = pm.generate_password();
                        std::cout << "Generated password: " << entry.password << std::endl;
                    }
                    
                    std::cout << "Notes: "; std::getline(std::cin, entry.notes);
                    pm.add_entry(entry);
                    break;
                }
                case 2: {
                    std::string service;
                    std::cout << "Enter service to search: ";
                    std::getline(std::cin, service);
                    
                    auto entries = pm.find_entries(service);
                    for (const auto& e : entries) {
                        std::cout << "\nService: " << e.service
                                  << "\nUsername: " << e.username
                                  << "\nPassword: " << e.password
                                  << "\nNotes: " << e.notes << "\n";
                    }
                    break;
                }
                case 3: {
                    auto pwd = pm.generate_password();
                    std::cout << "Generated password: " << pwd << std::endl;
                    break;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}