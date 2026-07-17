// Simple Login and Registration System in C++
// Compile: g++ -std=c++17 auth_system.cpp -o auth_system
// Run:     ./auth_system

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <cctype>
#include <functional>
#include <limits>
#include <random>

const std::string USER_FILE = "users.txt";

// ---------- Utility: hash a password with a salt ----------
// Uses std::hash iteratively so we don't need an external crypto library.
// (For real-world apps, prefer bcrypt/argon2/scrypt.)
std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string combined = salt + password;
    std::hash<std::string> hasher;
    size_t h = hasher(combined);
    // Strengthen a bit by rehashing
    for (int i = 0; i < 1000; ++i) {
        h = hasher(std::to_string(h) + salt);
    }
    std::stringstream ss;
    ss << std::hex << h;
    return ss.str();
}

std::string generateSalt(size_t length = 16) {
    static const char charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string salt;
    salt.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        salt += charset[dist(gen)];
    }
    return salt;
}

// ---------- Validation ----------
bool isValidUsername(const std::string& username) {
    if (username.length() < 3 || username.length() > 20) return false;
    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
    }
    return true;
}

bool isValidPassword(const std::string& password) {
    if (password.length() < 6) return false;
    bool hasLetter = false, hasDigit = false;
    for (char c : password) {
        if (std::isalpha(static_cast<unsigned char>(c))) hasLetter = true;
        if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
    }
    return hasLetter && hasDigit;
}

// ---------- File helpers ----------
bool userExists(const std::string& username) {
    std::ifstream in(USER_FILE);
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        std::stringstream ss(line);
        std::string storedUser;
        if (std::getline(ss, storedUser, ':')) {
            if (storedUser == username) return true;
        }
    }
    return false;
}

bool getUserRecord(const std::string& username,
                   std::string& salt, std::string& hash) {
    std::ifstream in(USER_FILE);
    if (!in.is_open()) return false;

    std::string line;
    while (std::getline(in, line)) {
        std::stringstream ss(line);
        std::string storedUser, storedSalt, storedHash;
        if (std::getline(ss, storedUser, ':') &&
            std::getline(ss, storedSalt, ':') &&
            std::getline(ss, storedHash)) {
            if (storedUser == username) {
                salt = storedSalt;
                hash = storedHash;
                return true;
            }
        }
    }
    return false;
}

// ---------- Registration ----------
void registerUser() {
    std::string username, password, confirm;

    std::cout << "\n--- Register ---\n";
    std::cout << "Enter username (3-20 chars, letters/digits/underscore): ";
    std::cin >> username;

    if (!isValidUsername(username)) {
        std::cout << "[ERROR] Invalid username format.\n";
        return;
    }

    if (userExists(username)) {
        std::cout << "[ERROR] Username '" << username << "' already exists.\n";
        return;
    }

    std::cout << "Enter password (min 6 chars, must include letters & digits): ";
    std::cin >> password;

    if (!isValidPassword(password)) {
        std::cout << "[ERROR] Weak password. Must be at least 6 chars and contain letters and digits.\n";
        return;
    }

    std::cout << "Confirm password: ";
    std::cin >> confirm;

    if (password != confirm) {
        std::cout << "[ERROR] Passwords do not match.\n";
        return;
    }

    std::string salt = generateSalt();
    std::string hashed = hashPassword(password, salt);

    std::ofstream out(USER_FILE, std::ios::app);
    if (!out.is_open()) {
        std::cout << "[ERROR] Cannot open user data file for writing.\n";
        return;
    }
    out << username << ":" << salt << ":" << hashed << "\n";
    out.close();

    std::cout << "[SUCCESS] Registration successful. Welcome, " << username << "!\n";
}

// ---------- Login ----------
void loginUser() {
    std::string username, password;

    std::cout << "\n--- Login ---\n";
    std::cout << "Username: ";
    std::cin >> username;
    std::cout << "Password: ";
    std::cin >> password;

    std::string salt, storedHash;
    if (!getUserRecord(username, salt, storedHash)) {
        std::cout << "[ERROR] User not found.\n";
        return;
    }

    std::string attemptHash = hashPassword(password, salt);
    if (attemptHash == storedHash) {
        std::cout << "[SUCCESS] Login successful. Hello, " << username << "!\n";
    } else {
        std::cout << "[ERROR] Incorrect password.\n";
    }
}

// ---------- Main menu ----------
int main() {
    std::cout << "=== Login / Registration System ===\n";

    while (true) {
        std::cout << "\n1. Register\n"
                  << "2. Login\n"
                  << "3. Exit\n"
                  << "Choose an option: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "[ERROR] Invalid input.\n";
            continue;
        }

        switch (choice) {
            case 1: registerUser(); break;
            case 2: loginUser();    break;
            case 3:
                std::cout << "Goodbye!\n";
                return 0;
            default:
                std::cout << "[ERROR] Invalid option.\n";
        }
    }
}
