# Password Manager
This project is a console-based application designed for the secure storage and management of user passwords. The program allows users to save credentials for various services, protecting them with symmetric encryption using AES-256-CBC. All data is stored in an encrypted local file, accessible only after entering a master password.

## Features
- **Master Password Management**: Set up and verify a master password to access the password vault.
- **Encryption/Decryption**: Securely encrypt and decrypt the password database using AES-256-CBC encryption.
- **Add Entries**: Add new records including service name, username, password, and notes.
- **Search Entries**: Search for records by service name or username.
- **Edit and Delete**: Modify or remove existing password entries.
- **Password Generation**: Generate secure passwords with customizable parameters (length, character types).
- **Command-Line Interface**: User-friendly interaction through a command-line menu.

## Installation
1. Install dependencies:
   ```bash
   brew install openssl nlohmann-json
2. Clone repository
   git clone https://github.com/Ye2312/password-manager.git
   cd password-manager
3. Build the project
   mkdir build && cd build
   cmake ..
   make
## Usage
1. Run the program
   ./password_manager
2. Follow the menu propmts to manage enrties and passwords
## Testing
1. ctest
## Documentation
1. doxygen Doxyfile.in
2. open docs/html/index.html

