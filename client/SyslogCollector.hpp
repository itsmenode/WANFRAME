#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <netinet/in.h>

namespace net_ops::client
{
    class SyslogCollector
    {
    public:
        using LogCallback = std::function<void(const std::string&, const std::string&)>;

        explicit SyslogCollector(const std::string &logPath = "/var/log/syslog");
        ~SyslogCollector();

        void Start(int port, LogCallback callback);
        void Stop();

    private:
        void ReceiveLoop(int port);

        std::string m_path;
        std::thread m_worker;
        std::atomic<bool> m_running;
        LogCallback m_callback;
        int m_server_fd;
    };
}