#include "password_manager.h"
#include "crypto.h"
#include <iostream>
#include <string>
#include <termios.h>
#include <unistd.h>

// Скрываем ввод пароля (для Unix-систем)
std::string get_hidden_input(const std::string& prompt) {
    std::cout << prompt;
    
    termios old_settings;
    tcgetattr(STDIN_FILENO, &old_settings);
    
    termios new_settings = old_settings;
    new_settings.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    
    std::string input;
    std::getline(std::cin, input);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    std::cout << "\n";
    
    return input;
}

// Вывод меню
void print_menu() {
    std::cout << "\n🔐 Password Manager 🔐\n"
              << "1. Add new password entry\n"
              << "2. Find entries by service\n"
              << "3. Generate random password\n"
              << "4. List all entries\n"
              << "5. Exit\n"
              << "> ";
}

int main() {
    PasswordManager manager;
    
    try {
        // Инициализация мастер-паролем
        std::string master_password = get_hidden_input("Enter master password: ");
        manager.initialize(master_password);
        
        int choice = 0;
        while (choice != 5) {
            print_menu();
            std::cin >> choice;
            std::cin.ignore(); // Очищаем буфер
            
            switch (choice) {
                case 1: { // Добавление записи
                    PasswordEntry entry;
                    std::cout << "Service: ";
                    std::getline(std::cin, entry.service);
                    
                    std::cout << "Username: ";
                    std::getline(std::cin, entry.username);
                    
                    std::cout << "Password (leave empty to generate): ";
                    entry.password = get_hidden_input("");
                    
                    if (entry.password.empty()) {
                        entry.password = manager.generate_password();
                        std::cout << "Generated: " << entry.password << "\n";
                    }
                    
                    std::cout << "Notes: ";
                    std::getline(std::cin, entry.notes);
                    
                    manager.add_entry(entry);
                    std::cout << "✅ Entry added!\n";
                    break;
                }
                
                case 2: { // Поиск по сервису
                    std::string service;
                    std::cout << "Enter service name: ";
                    std::getline(std::cin, service);
                    
                    auto entries = manager.find_entries(service);
                    if (entries.empty()) {
                        std::cout << "No entries found.\n";
                    } else {
                        for (const auto& e : entries) {
                            std::cout << "\nService: " << e.service
                                      << "\nUsername: " << e.username
                                      << "\nPassword: " << e.password
                                      << "\nNotes: " << e.notes << "\n";
                        }
                    }
                    break;
                }
                
                case 3: { // Генерация пароля
                    int length;
                    std::cout << "Password length (default 16): ";
                    std::cin >> length;
                    
                    if (length < 8) length = 16;
                    
                    std::string password = manager.generate_password(length);
                    std::cout << "🔑 Generated: " << password << "\n";
                    break;
                }
                
                case 4: { // Показать все записи
                    auto entries = manager.find_entries(""); // Пустой запрос = все записи
                    for (const auto& e : entries) {
                        std::cout << "\nService: " << e.service
                                  << "\nUsername: " << e.username << "\n";
                    }
                    break;
                }
                
                case 5: // Выход
                    std::cout << "Goodbye!\n";
                    break;
                    
                default:
                    std::cout << "Invalid choice!\n";
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}