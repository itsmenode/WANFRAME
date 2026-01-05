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

    struct GroupRecord {
        int id;
        std::string name;
        int owner_id;
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
            std::optional<UserRecord> GetUserById(int id);

            int CreateGroup(const std::string& group_name, int owner_id);
            bool AddMemberToGroup(int user_id, int group_id);
            std::vector<GroupRecord> GetGroupsForUser(int user_id);
    };
}