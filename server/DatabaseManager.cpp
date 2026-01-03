#include "DatabaseManager.hpp"
#include <iostream>

namespace net_ops::server {

    DatabaseManager& DatabaseManager::GetInstance() {
        static DatabaseManager instance;
        return instance;
    }

    DatabaseManager::DatabaseManager() 
        : db_(nullptr), stmt_insert_user_(nullptr), stmt_get_user_(nullptr) {}

    DatabaseManager::~DatabaseManager() {
        Shutdown();
    }

    bool DatabaseManager::Initialize(const std::string& db_path) {
        std::lock_guard<std::mutex> lock(db_mutex_);

        if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
            std::cerr << "[DB] Open failed: " << sqlite3_errmsg(db_) << std::endl;
            return false;
        }

        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

        const char* sql_table = 
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT UNIQUE NOT NULL, "
            "password_hash BLOB NOT NULL, "
            "salt BLOB NOT NULL"
            ");";
        
        char* err_msg = nullptr;
        if (sqlite3_exec(db_, sql_table, nullptr, nullptr, &err_msg) != SQLITE_OK) {
            std::cerr << "[DB] Schema error: " << err_msg << std::endl;
            sqlite3_free(err_msg);
            return false;
        }

        sqlite3_prepare_v2(db_, "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?);", -1, &stmt_insert_user_, nullptr);
        sqlite3_prepare_v2(db_, "SELECT id, username, password_hash, salt FROM users WHERE username = ?;", -1, &stmt_get_user_, nullptr);

        return true;
    }

    void DatabaseManager::Shutdown() {
        std::lock_guard<std::mutex> lock(db_mutex_);
        if (stmt_insert_user_) sqlite3_finalize(stmt_insert_user_);
        if (stmt_get_user_) sqlite3_finalize(stmt_get_user_);
        
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    bool DatabaseManager::CreateUser(const std::string& username, const std::vector<uint8_t>& hash, const std::vector<uint8_t>& salt) {
        std::lock_guard<std::mutex> lock(db_mutex_);

        sqlite3_reset(stmt_insert_user_);
        sqlite3_bind_text(stmt_insert_user_, 1, username.c_str(), username.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt_insert_user_, 2, hash.data(), hash.size(), SQLITE_STATIC);
        sqlite3_bind_blob(stmt_insert_user_, 3, salt.data(), salt.size(), SQLITE_STATIC);

        if (sqlite3_step(stmt_insert_user_) != SQLITE_DONE) return false;
        return true;
    }

    std::optional<UserRecord> DatabaseManager::GetUserByName(const std::string& username) {
        std::lock_guard<std::mutex> lock(db_mutex_);

        sqlite3_reset(stmt_get_user_);
        sqlite3_bind_text(stmt_get_user_, 1, username.c_str(), username.size(), SQLITE_STATIC);

        if (sqlite3_step(stmt_get_user_) == SQLITE_ROW) {
            UserRecord user;
            user.id = sqlite3_column_int(stmt_get_user_, 0);
            
            const char* name_ptr = reinterpret_cast<const char*>(sqlite3_column_text(stmt_get_user_, 1));
            if (name_ptr) user.username = name_ptr;
            
            const void* hash_ptr = sqlite3_column_blob(stmt_get_user_, 2);
            int hash_size = sqlite3_column_bytes(stmt_get_user_, 2);
            user.password_hash.assign((const uint8_t*)hash_ptr, (const uint8_t*)hash_ptr + hash_size);

            const void* salt_ptr = sqlite3_column_blob(stmt_get_user_, 3);
            int salt_size = sqlite3_column_bytes(stmt_get_user_, 3);
            user.salt.assign((const uint8_t*)salt_ptr, (const uint8_t*)salt_ptr + salt_size);

            return user;
        }
        
        return std::nullopt;
    }
}