#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <sqlite3.h>

namespace net_ops::server
{

    struct UserRecord
    {
        int id;
        std::string username;
        std::vector<uint8_t> password_hash;
        std::vector<uint8_t> salt;
    };

    struct GroupRecord
    {
        int id;
        std::string name;
        int owner_id;
    };

    struct DeviceRecord
    {
        int id;
        int owner_id;
        int group_id;
        std::string name;
        std::string ip_address;
        std::string mac_address;
        std::string status;
        std::string info;
    };

    struct LogEntry
    {
        std::string timestamp;
        std::string message;
    };

    class DatabaseManager
    {
    private:
        sqlite3 *db_;
        std::mutex db_mutex_;

        sqlite3_stmt *stmt_insert_user_;
        sqlite3_stmt *stmt_get_user_;

        DatabaseManager();
        ~DatabaseManager();

    public:
        static DatabaseManager &GetInstance();

        DatabaseManager(const DatabaseManager &) = delete;
        DatabaseManager &operator=(const DatabaseManager &) = delete;

        bool Initialize(const std::string &db_path);
        void Shutdown();

        bool CreateUser(const std::string &username, const std::string &password);
        std::optional<UserRecord> GetUserByName(const std::string &username);
        std::optional<UserRecord> GetUserById(int id);

        bool ValidateUser(const std::string &username, const std::string &password);

        int CreateGroup(const std::string &group_name, int owner_id);
        bool AddMemberToGroup(int user_id, int group_id);
        std::vector<GroupRecord> GetGroupsForUser(int user_id);
        bool IsGroupOwner(int group_id, int user_id);

        bool AddDevice(int user_id, int group_id, const std::string &name, const std::string &ip, std::string mac);
        std::vector<DeviceRecord> GetAllDevicesForUser(int user_id);
        std::vector<DeviceRecord> GetDevicesInGroup(int group_id);
        void UpdateDeviceStatus(const std::string &ip, const std::string &status, const std::string &info);

        void SaveLog(const std::string &ip_address, const std::string &message);

        std::vector<LogEntry> GetLogsForDevice(int device_id, int limit = 50);
    };
}