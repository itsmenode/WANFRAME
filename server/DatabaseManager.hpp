#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <thread>

#include <sqlite3.h>

namespace net_ops::server {
    struct UserRecord {
        int id;
        std::string username;
        std::vector<uint8_t> password_hash;
        std::vector<uint8_t> salt;
    };

    class DatabaseManager {
        private:
            sqlite3* db_;
            std::mutex db_mutex_;
            sqlite3_stmt* stmt_insert_user_;
            sqlite3_stmt* stmt_get_user_;

            DatabaseManager();
            ~DatabaseManager();
        public:
            static DatabaseManager& GetInstance();

            DatabaseManager(const DatabaseManager&) = delete;
            DatabaseManager& operator=(const DatabaseManager&) = delete;

            bool Initialize(const std::string& db_path);
            void Shutdown();

            bool CreateUser(const std::string& username, const std::vector<uint8_t>& hash, const std::vector<uint8_t>& salt);
            std::optional<UserRecord> GetUserByName(const std::string& username);
    };
}