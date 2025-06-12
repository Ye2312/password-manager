#pragma once
#include <string>
#include <vector>

struct PasswordEntry {
    std::string service;  
    std::string username; 
    std::string password; 
    std::string notes;    
};

class PasswordManager {
public:
    PasswordManager(const std::string& masterPassword);
    bool addEntry(const PasswordEntry& entry);
    
    std::vector<PasswordEntry> findEntries(const std::string& service) const;
    
    bool removeEntry(const std::string& service, const std::string& username);
    
    std::string generatePassword(int length, bool useSymbols) const;
    
private:
    std::string masterPassword_;  
    std::vector<PasswordEntry> entries_;  
    
    void loadEntries();
    
    void saveEntries() const;
};