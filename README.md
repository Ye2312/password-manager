# Password Manager

A secure password manager implemented in C++ using AES-256-CBC encryption.

## Features
- Add, edit, delete, and search password entries.
- Generate secure passwords with customizable settings.
- Encrypted storage with master password protection.

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

