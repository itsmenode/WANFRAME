#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <optional>

namespace net_ops::server
{
    class SessionManager
    {
    private:
        std::unordered_map<std::string, int> m_sessions;
        std::mutex m_mutex;

        SessionManager() = default;

    public:
        static SessionManager &GetInstance();

        std::string CreateSession(int userId);

        std::optional<int> GetUserId(const std::string &token);

        bool RemoveSession(const std::string &token);
    };
}
