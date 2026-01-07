#pragma once
#include <string>
#include <thread>
#include <atomic>

namespace net_ops::client
{
    class SyslogCollector
    {
    public:
        SyslogCollector(const std::string &logPath = "/var/log/syslog");
        ~SyslogCollector();
        void Start();
        void Stop();

    private:
        void MonitorLoop();
        std::string m_path;
        std::thread m_worker;
        std::atomic<bool> m_running;
    };
}