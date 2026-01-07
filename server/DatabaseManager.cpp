#include "DatabaseManager.hpp"
#include <iostream>
#include <vector>
#include <mutex>
#include <optional>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>

namespace net_ops::server
{
    static std::vector<uint8_t> InternalPBKDF2(const std::string &password, const std::vector<uint8_t> &salt)
    {
        std::vector<uint8_t> hash(32);
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          10000,
                          EVP_sha256(),
                          hash.size(), hash.data());
        return hash;
    }

    DatabaseManager &DatabaseManager::GetInstance()
    {
        static DatabaseManager instance;
        return instance;
    }

    DatabaseManager::DatabaseManager() : db_(nullptr), stmt_insert_user_(nullptr), stmt_get_user_(nullptr) {}

    DatabaseManager::~DatabaseManager()
    {
        Shutdown();
    }

    bool DatabaseManager::Initialize(const std::string &db_path)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);

        if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK)
        {
            std::cerr << "[DB] Open failed: " << sqlite3_errmsg(db_) << std::endl;
            return false;
        }

        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);

        const char *sql_tables =
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT UNIQUE NOT NULL, "
            "password_hash BLOB NOT NULL, "
            "salt BLOB NOT NULL"
            ");"

            "CREATE TABLE IF NOT EXISTS groups ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT NOT NULL, "
            "owner_id INTEGER, "
            "FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE"
            ");"

            "CREATE TABLE IF NOT EXISTS group_members ("
            "group_id INTEGER, "
            "user_id INTEGER, "
            "UNIQUE(group_id, user_id), "
            "FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE, "
            "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE"
            ");"

            "CREATE TABLE IF NOT EXISTS physical_devices ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "mac_address TEXT UNIQUE NOT NULL, "
            "ip_address TEXT NOT NULL, "
            "status TEXT DEFAULT 'UNKNOWN', "
            "last_seen DATETIME DEFAULT CURRENT_TIMESTAMP"
            ");"

            "CREATE TABLE IF NOT EXISTS user_devices ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_id INTEGER NOT NULL, "
            "physical_id INTEGER NOT NULL, "
            "group_id INTEGER, "
            "custom_name TEXT NOT NULL, "
            "custom_info TEXT DEFAULT '', "
            "UNIQUE(user_id, physical_id), "
            "FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, "
            "FOREIGN KEY(physical_id) REFERENCES physical_devices(id) ON DELETE CASCADE, "
            "FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE SET NULL"
            ");"

            "CREATE TABLE IF NOT EXISTS logs ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "physical_id INTEGER, "
            "received_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
            "message TEXT, "
            "FOREIGN KEY(physical_id) REFERENCES physical_devices(id) ON DELETE CASCADE"
            ");";

        char *err_msg = nullptr;
        if (sqlite3_exec(db_, sql_tables, nullptr, nullptr, &err_msg) != SQLITE_OK)
        {
            std::cerr << "[DB] Schema error: " << err_msg << std::endl;
            sqlite3_free(err_msg);
            return false;
        }
        return true;
    }

    void DatabaseManager::Shutdown()
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        if (stmt_insert_user_)
        {
            sqlite3_finalize(stmt_insert_user_);
            stmt_insert_user_ = nullptr;
        }
        if (stmt_get_user_)
        {
            sqlite3_finalize(stmt_get_user_);
            stmt_get_user_ = nullptr;
        }
        if (db_)
        {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    bool DatabaseManager::CreateUser(const std::string &username, const std::string &password)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        std::vector<uint8_t> salt(16);
        if (RAND_bytes(salt.data(), 16) != 1)
            return false;
        std::vector<uint8_t> hash = InternalPBKDF2(password, salt);

        const char *sql = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?);";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 2, hash.data(), static_cast<int>(hash.size()), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 3, salt.data(), static_cast<int>(salt.size()), SQLITE_TRANSIENT);

        bool success = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return success;
    }

    bool DatabaseManager::ValidateUser(const std::string &username, const std::string &password)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        const char *sql = "SELECT password_hash, salt FROM users WHERE username = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        std::vector<uint8_t> storedHash, salt;
        bool userFound = false;
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            userFound = true;
            const void *h = sqlite3_column_blob(stmt, 0);
            int h_len = sqlite3_column_bytes(stmt, 0);
            if (h)
                storedHash.assign((const uint8_t *)h, (const uint8_t *)h + h_len);
            const void *s = sqlite3_column_blob(stmt, 1);
            int s_len = sqlite3_column_bytes(stmt, 1);
            if (s)
                salt.assign((const uint8_t *)s, (const uint8_t *)s + s_len);
        }
        sqlite3_finalize(stmt);

        if (!userFound || salt.empty() || storedHash.empty())
            return false;
        return (InternalPBKDF2(password, salt) == storedHash);
    }

    std::optional<UserRecord> DatabaseManager::GetUserByName(const std::string &username)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        const char *sql = "SELECT id, username, password_hash, salt FROM users WHERE username = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return std::nullopt;

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        std::optional<UserRecord> result = std::nullopt;
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            UserRecord user;
            user.id = sqlite3_column_int(stmt, 0);
            const char *name_ptr = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            if (name_ptr)
                user.username = name_ptr;
            const void *hash_ptr = sqlite3_column_blob(stmt, 2);
            int hash_size = sqlite3_column_bytes(stmt, 2);
            const void *salt_ptr = sqlite3_column_blob(stmt, 3);
            int salt_size = sqlite3_column_bytes(stmt, 3);
            if (hash_ptr && hash_size > 0)
                user.password_hash.assign((const uint8_t *)hash_ptr, (const uint8_t *)hash_ptr + hash_size);
            if (salt_ptr && salt_size > 0)
                user.salt.assign((const uint8_t *)salt_ptr, (const uint8_t *)salt_ptr + salt_size);
            result = user;
        }
        sqlite3_finalize(stmt);
        return result;
    }

    std::optional<UserRecord> DatabaseManager::GetUserById(int id)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        const char *sql = "SELECT id, username, password_hash, salt FROM users WHERE id = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return std::nullopt;

        sqlite3_bind_int(stmt, 1, id);
        std::optional<UserRecord> result = std::nullopt;
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            UserRecord user;
            user.id = sqlite3_column_int(stmt, 0);
            const char *name_ptr = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            if (name_ptr)
                user.username = name_ptr;
            const void *hash_ptr = sqlite3_column_blob(stmt, 2);
            int hash_size = sqlite3_column_bytes(stmt, 2);
            const void *salt_ptr = sqlite3_column_blob(stmt, 3);
            int salt_size = sqlite3_column_bytes(stmt, 3);
            if (hash_ptr)
                user.password_hash.assign((const uint8_t *)hash_ptr, (const uint8_t *)hash_ptr + hash_size);
            if (salt_ptr)
                user.salt.assign((const uint8_t *)salt_ptr, (const uint8_t *)salt_ptr + salt_size);
            result = user;
        }
        sqlite3_finalize(stmt);
        return result;
    }

    int DatabaseManager::CreateGroup(const std::string &group_name, int owner_id)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, "INSERT INTO groups (name, owner_id) VALUES (?, ?);", -1, &stmt, nullptr) != SQLITE_OK)
            return -1;
        sqlite3_bind_text(stmt, 1, group_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, owner_id);
        int new_id = -1;
        if (sqlite3_step(stmt) == SQLITE_DONE)
            new_id = (int)sqlite3_last_insert_rowid(db_);
        sqlite3_finalize(stmt);
        return new_id;
    }

    bool DatabaseManager::AddMemberToGroup(int user_id, int group_id)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?);", -1, &stmt, nullptr) != SQLITE_OK)
            return false;
        sqlite3_bind_int(stmt, 1, group_id);
        sqlite3_bind_int(stmt, 2, user_id);
        bool success = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return success;
    }

    std::vector<GroupRecord> DatabaseManager::GetGroupsForUser(int user_id)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        std::vector<GroupRecord> groups;
        const char *sql = "SELECT DISTINCT g.id, g.name, g.owner_id FROM groups g "
                          "LEFT JOIN group_members gm ON g.id = gm.group_id "
                          "WHERE g.owner_id = ? OR gm.user_id = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return groups;
        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, user_id);
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            GroupRecord g;
            g.id = sqlite3_column_int(stmt, 0);
            const char *name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            if (name)
                g.name = name;
            g.owner_id = sqlite3_column_int(stmt, 2);
            groups.push_back(g);
        }
        sqlite3_finalize(stmt);
        return groups;
    }

    bool DatabaseManager::IsGroupOwner(int group_id, int user_id)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, "SELECT 1 FROM groups WHERE id = ? AND owner_id = ?;", -1, &stmt, nullptr) != SQLITE_OK)
            return false;
        sqlite3_bind_int(stmt, 1, group_id);
        sqlite3_bind_int(stmt, 2, user_id);
        bool is_owner = (sqlite3_step(stmt) == SQLITE_ROW);
        sqlite3_finalize(stmt);
        return is_owner;
    }

    std::string StandardizeMac(std::string mac)
    {
        std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
        return mac;
    }

    bool DatabaseManager::AddDevice(int user_id, int group_id, const std::string &name, const std::string &ip, std::string mac)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        mac = StandardizeMac(mac);

        const char *phys_sql = "INSERT OR IGNORE INTO physical_devices (mac_address, ip_address) VALUES (?, ?);";
        sqlite3_stmt *stmt;
        sqlite3_prepare_v2(db_, phys_sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, mac.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        const char *upd_phys = "UPDATE physical_devices SET ip_address = ?, status = 'ACTIVE', last_seen = CURRENT_TIMESTAMP WHERE mac_address = ?;";
        sqlite3_prepare_v2(db_, upd_phys, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, mac.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        int phys_id = -1;
        sqlite3_prepare_v2(db_, "SELECT id FROM physical_devices WHERE mac_address = ?;", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, mac.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            phys_id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);

        const char *user_dev_sql = "INSERT OR REPLACE INTO user_devices (user_id, physical_id, group_id, custom_name) VALUES (?, ?, ?, ?);";
        sqlite3_prepare_v2(db_, user_dev_sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, phys_id);
        if (group_id <= 0)
            sqlite3_bind_null(stmt, 3);
        else
            sqlite3_bind_int(stmt, 3, group_id);
        sqlite3_bind_text(stmt, 4, name.c_str(), -1, SQLITE_TRANSIENT);

        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        return ok;
    }

    std::vector<DeviceRecord> DatabaseManager::GetAllDevicesForUser(int user_id)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        std::vector<DeviceRecord> devices;
        const char *sql = "SELECT ud.id, ud.user_id, ud.group_id, ud.custom_name, pd.ip_address, pd.mac_address, pd.status, ud.custom_info "
                          "FROM user_devices ud "
                          "JOIN physical_devices pd ON ud.physical_id = pd.id "
                          "WHERE ud.user_id = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return devices;
        sqlite3_bind_int(stmt, 1, user_id);
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            DeviceRecord d;
            d.id = sqlite3_column_int(stmt, 0);
            d.owner_id = sqlite3_column_int(stmt, 1);
            d.group_id = sqlite3_column_int(stmt, 2);
            d.name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
            d.ip_address = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
            d.mac_address = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
            d.status = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
            const char *info = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 7));
            if (info)
                d.info = info;
            devices.push_back(d);
        }
        sqlite3_finalize(stmt);
        return devices;
    }

    std::vector<DeviceRecord> DatabaseManager::GetDevicesInGroup(int group_id)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        std::vector<DeviceRecord> devices;
        const char *sql = "SELECT ud.id, ud.user_id, ud.group_id, ud.custom_name, pd.ip_address, pd.mac_address, pd.status, ud.custom_info "
                          "FROM user_devices ud "
                          "JOIN physical_devices pd ON ud.physical_id = pd.id "
                          "WHERE ud.group_id = ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return devices;
        sqlite3_bind_int(stmt, 1, group_id);
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            DeviceRecord d;
            d.id = sqlite3_column_int(stmt, 0);
            d.owner_id = sqlite3_column_int(stmt, 1);
            d.group_id = sqlite3_column_int(stmt, 2);
            d.name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
            d.ip_address = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
            d.mac_address = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
            d.status = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
            const char *info = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 7));
            if (info)
                d.info = info;
            devices.push_back(d);
        }
        sqlite3_finalize(stmt);
        return devices;
    }

    void DatabaseManager::SaveLog(const std::string &ip_address, const std::string &message)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt *stmt;
        int phys_id = -1;

        const char *find_sql = "SELECT id FROM physical_devices WHERE ip_address = ? LIMIT 1;";
        if (sqlite3_prepare_v2(db_, find_sql, -1, &stmt, nullptr) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, ip_address.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                phys_id = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        if (phys_id == -1)
        {
            const char *insert_phys = "INSERT OR IGNORE INTO physical_devices (mac_address, ip_address, status) VALUES (?, ?, 'Online');";
            if (sqlite3_prepare_v2(db_, insert_phys, -1, &stmt, nullptr) == SQLITE_OK)
            {
                std::string placeholder_mac = "AUTO_" + ip_address;
                sqlite3_bind_text(stmt, 1, placeholder_mac.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, ip_address.c_str(), -1, SQLITE_TRANSIENT);
                if (sqlite3_step(stmt) == SQLITE_DONE)
                {
                    phys_id = static_cast<int>(sqlite3_last_insert_rowid(db_));
                }
                sqlite3_finalize(stmt);
            }
        }

        if (phys_id != -1)
        {
            const char *log_sql = "INSERT INTO logs (physical_id, message) VALUES (?, ?);";
            if (sqlite3_prepare_v2(db_, log_sql, -1, &stmt, nullptr) == SQLITE_OK)
            {
                sqlite3_bind_int(stmt, 1, phys_id);
                sqlite3_bind_text(stmt, 2, message.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }

    std::vector<LogEntry> DatabaseManager::GetLogsForDevice(int user_device_id, int limit)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        std::vector<LogEntry> logs;
        const char *sql = "SELECT l.received_at, l.message FROM logs l "
                          "JOIN user_devices ud ON l.physical_id = ud.physical_id "
                          "WHERE ud.id = ? ORDER BY l.id DESC LIMIT ?;";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return logs;
        sqlite3_bind_int(stmt, 1, user_device_id);
        sqlite3_bind_int(stmt, 2, limit);
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            LogEntry entry;
            entry.timestamp = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            entry.message = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            logs.push_back(entry);
        }
        sqlite3_finalize(stmt);
        return logs;
    }

    void DatabaseManager::UpdateDeviceStatus(const std::string &ip, const std::string &status, const std::string &info)
    {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db_, "UPDATE physical_devices SET status = ?, last_seen = CURRENT_TIMESTAMP WHERE ip_address = ?;", -1, &stmt, nullptr) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
}