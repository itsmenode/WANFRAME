#pragma once

#include <string>
#include <thread>
#include <atomic>
#include "DataSource.hpp"

namespace net_ops::client
{
    class SyslogCollector : public DataSource
    {
    public:
        explicit SyslogCollector(const std::string &logPath, int port = 0);
        ~SyslogCollector();

        void SetPort(int port);
        void Start(DataCallback callback) override;

        void Stop() override;

    private:
        std::string m_logPath;
        int m_port;
        std::atomic<bool> m_running;
        std::thread m_worker;
    };
}
