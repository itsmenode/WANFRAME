#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include <netinet/in.h>

namespace net_ops::client
{
    class SyslogCollector
    {
    public:
        using LogCallback = std::function<void(const std::string &, const std::string &)>;

        explicit SyslogCollector(const std::string &logPath = "/var/log/syslog");
        ~SyslogCollector();

        void Start(int port, LogCallback callback);
        void Stop();

    private:
        void ReceiveLoop(int port);
        void FileMonitorLoop();

        std::string m_path;
        LogCallback m_callback;
        std::atomic<bool> m_running;

        std::thread m_udp_worker;
        std::thread m_file_worker;

        int m_udp_fd;
        int m_inotify_fd;
    };
}