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

    struct DeviceRecord
    {
        int id;
        int owner_id;
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

    struct DeviceMetrics
    {
        int device_id;
        int log_count;
        std::string last_status;
    };

    class DatabaseManager
    {
    private:
        sqlite3 *db_;
        std::mutex db_mutex_;

        DatabaseManager();
        ~DatabaseManager();

    public:
        static DatabaseManager &GetInstance();

        std::vector<DeviceMetrics> GetGlobalMetrics();

        DatabaseManager(const DatabaseManager &) = delete;
        DatabaseManager &operator=(const DatabaseManager &) = delete;

        bool Initialize(const std::string &db_path);
        void Shutdown();

        bool CreateUser(const std::string &username, const std::string &password);
        std::optional<UserRecord> GetUserByName(const std::string &username);
        std::optional<UserRecord> GetUserById(int id);

        bool ValidateUser(const std::string &username, const std::string &password);

        bool AddDevice(int user_id, const std::string &name, const std::string &ip, std::string mac);
        std::vector<DeviceRecord> GetAllDevicesForUser(int user_id);
        bool IsUserDeviceOwner(int user_id, int user_device_id);
        void UpdateDeviceStatus(const std::string &ip, const std::string &status, const std::string &info);

        void SaveLog(const std::string &ip_address, const std::string &message);
        std::vector<LogEntry> GetLogsForDevice(int user_device_id, int limit = 50);

        std::optional<std::string> GetDashboardConfig(int user_id);
        bool SetDashboardConfig(int user_id, const std::string &config);
    };
}
