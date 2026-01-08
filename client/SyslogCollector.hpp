#pragma once

#include <string>
#include <thread>
#include <functional>
#include <atomic>

namespace net_ops::client
{
    using LogCallback = std::function<void(const std::string &source, const std::string &message)>;

    class SyslogCollector
    {
    public:
        explicit SyslogCollector(const std::string &logPath);
        ~SyslogCollector();

        void Start(int port, LogCallback callback);

        void Stop();

    private:
        std::string m_logPath;
        std::atomic<bool> m_running;
        std::thread m_worker;
    };
}