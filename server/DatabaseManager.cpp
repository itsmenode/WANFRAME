#include "DatabaseManager.hpp"
#include <iostream>

namespace net_ops::server {

    DatabaseManager& DatabaseManager::GetInstance() {
        static DatabaseManager instance;
        return instance;
    }

    DatabaseManager::DatabaseManager(): db_(nullptr), stmt_insert_user_(nullptr), stmt_get_user_(nullptr) {}

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

        const char* sql_tables = 
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT UNIQUE NOT NULL, "
            "password_hash BLOB NOT NULL, "
            "salt BLOB NOT NULL"
            ");"
            
            "CREATE TABLE IF NOT EXISTS groups ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT UNIQUE NOT NULL, "
            "owner_id INTEGER, "
            "FOREIGN KEY(owner_id) REFERENCES users(id)"
            ");"

            "CREATE TABLE IF NOT EXISTS group_members ("
            "group_id INTEGER, "
            "user_id INTEGER, "
            "joined_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
            "PRIMARY KEY (group_id, user_id), "
            "FOREIGN KEY(group_id) REFERENCES groups(id), "
            "FOREIGN KEY(user_id) REFERENCES users(id)"
            ");";
        
        char* err_msg = nullptr;
        if (sqlite3_exec(db_, sql_tables, nullptr, nullptr, &err_msg) != SQLITE_OK) {
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
        if (stmt_insert_user_) {
            sqlite3_finalize(stmt_insert_user_);
            stmt_insert_user_ = nullptr;
        }
        if (stmt_get_user_) {
            sqlite3_finalize(stmt_get_user_);
            stmt_get_user_ = nullptr;
        }
        
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

    std::optional<UserRecord> DatabaseManager::GetUserById(int id) {
        std::lock_guard<std::mutex> lock(db_mutex_);
        
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "SELECT id, username, password_hash, salt FROM users WHERE id = ?;", -1, &stmt, nullptr) != SQLITE_OK) {
            return std::nullopt;
        }
        
        sqlite3_bind_int(stmt, 1, id);

        std::optional<UserRecord> result = std::nullopt;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            UserRecord user;
            user.id = sqlite3_column_int(stmt, 0);

            const char* name_ptr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            if (name_ptr) user.username = name_ptr;

            const void* hash_ptr = sqlite3_column_blob(stmt, 2);
            int hash_size = sqlite3_column_bytes(stmt, 2);
            user.password_hash.assign((const uint8_t*)hash_ptr, (const uint8_t*)hash_ptr + hash_size);

            const void* salt_ptr = sqlite3_column_blob(stmt, 3);
            int salt_size = sqlite3_column_bytes(stmt, 3);
            user.salt.assign((const uint8_t*)salt_ptr, (const uint8_t*)salt_ptr + salt_size);

            result = user;
        }
        sqlite3_finalize(stmt);
        return result;
    }


    int DatabaseManager::CreateGroup(const std::string& group_name, int owner_id) {
        std::lock_guard<std::mutex> lock(db_mutex_);

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "INSERT INTO groups (name, owner_id) VALUES (?, ?);", -1, &stmt, nullptr) != SQLITE_OK) {
            return -1;
        }

        sqlite3_bind_text(stmt, 1, group_name.c_str(), group_name.size(), SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, owner_id);

        int new_id = -1;
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            new_id = (int)sqlite3_last_insert_rowid(db_);
            std::cout << "[DB] Created Group '" << group_name << "' with ID: " << new_id << std::endl;
        } else {
            std::cerr << "[DB] CreateGroup error: " << sqlite3_errmsg(db_) << std::endl;
        }

        sqlite3_finalize(stmt);
        return new_id;
    }

    bool DatabaseManager::AddMemberToGroup(int user_id, int group_id) {
        std::lock_guard<std::mutex> lock(db_mutex_);

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?);", -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_int(stmt, 1, group_id);
        sqlite3_bind_int(stmt, 2, user_id);

        bool success = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return success;
    }

    std::vector<GroupRecord> DatabaseManager::GetGroupsForUser(int user_id) {
        std::lock_guard<std::mutex> lock(db_mutex_);
        std::vector<GroupRecord> groups;

        sqlite3_stmt* stmt;
        
        const char* sql = 
            "SELECT DISTINCT g.id, g.name, g.owner_id "
            "FROM groups g "
            "LEFT JOIN group_members gm ON g.id = gm.group_id "
            "WHERE g.owner_id = ? OR gm.user_id = ?;";

        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "[DB] Prepare ListGroups failed: " << sqlite3_errmsg(db_) << "\n";
            return groups;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, user_id);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            GroupRecord g;
            g.id = sqlite3_column_int(stmt, 0);
            
            const char* name_ptr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            if (name_ptr) g.name = name_ptr;
            
            g.owner_id = sqlite3_column_int(stmt, 2);
            groups.push_back(g);
        }

        sqlite3_finalize(stmt);
        return groups;
    }

    bool DatabaseManager::IsGroupOwner(int group_id, int user_id) {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt* stmt;
        const char* sql = "SELECT 1 FROM groups WHERE id = ? AND owner_id = ?;";
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        
        sqlite3_bind_int(stmt, 1, group_id);
        sqlite3_bind_int(stmt, 2, user_id);
        
        bool is_owner = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);
        return is_owner;
    }
}