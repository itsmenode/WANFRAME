#pragma once

#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include "DataSource.hpp"

namespace net_ops::client {

    struct MonitoredDevice {
        std::string ip;
        bool is_online;
        std::chrono::steady_clock::time_point last_snmp_check; 
    };

    class DeviceMonitor : public DataSource {
    public:
        DeviceMonitor();
        ~DeviceMonitor();

        void Start(DataCallback callback) override;
        void Stop() override;
        void SetTargets(const std::vector<std::string>& ips);

    private:
        void MonitorLoop();

        DataCallback m_callback;
        std::atomic<bool> m_running;
        std::thread m_thread;
        
        std::vector<MonitoredDevice> m_targets;
        std::mutex m_mutex;
    };
}
