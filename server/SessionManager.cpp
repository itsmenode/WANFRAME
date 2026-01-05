#include "SessionManager.hpp"
#include <random>
#include <sstream>
#include <iomanip>

namespace net_ops::server
{

    SessionManager &SessionManager::GetInstance()
    {
        static SessionManager instance;
        return instance;
    }

    std::string SessionManager::CreateSession(int userId)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::random_device rd;
        std::stringstream ss;
        for (int i = 0; i < 4; ++i)
        {
            ss << std::hex << std::setw(8) << std::setfill('0') << rd();
        }
        std::string token = ss.str();

        m_sessions[token] = userId;
        return token;
    }

    std::optional<int> SessionManager::GetUserId(const std::string &token)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_sessions.find(token);
        if (it != m_sessions.end())
        {
            return it->second;
        }
        return std::nullopt;
    }

    void SessionManager::RemoveSession(const std::string &token)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_sessions.erase(token);
    }
}