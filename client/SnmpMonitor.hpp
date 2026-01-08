#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "DataSource.hpp"
#include "SnmpClient.hpp"

namespace net_ops::client
{
    class SnmpMonitor : public DataSource
    {
    public:
        explicit SnmpMonitor(std::chrono::milliseconds interval = std::chrono::seconds(30));
        ~SnmpMonitor();

        void Start(DataCallback callback) override;
        void Stop() override;
        void SetTargets(const std::vector<std::string> &ips);

    private:
        void MonitorLoop();
        void SleepInterval();

        DataCallback m_callback;
        std::atomic<bool> m_running;
        std::thread m_thread;
        std::vector<std::string> m_targets;
        std::mutex m_mutex;
        SnmpClient m_client;
        std::chrono::milliseconds m_interval;
    };
}
