#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>

namespace net_ops::client
{
    using LogCallback = std::function<void(const std::string &, const std::string &)>;

    class SyslogCollector
    {
    public:
        SyslogCollector(const std::string &logPath);
        ~SyslogCollector();

        int Start(int port, LogCallback callback);
        void Stop();

    private:
        std::string m_logPath;
        std::atomic<bool> m_running;
        std::thread m_udpWorker;
        std::thread m_fileWorker;
    };
}