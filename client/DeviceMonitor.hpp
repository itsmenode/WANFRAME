#pragma once
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>

namespace net_ops::client {

    struct MonitoredDevice {
        std::string ip;
        bool is_online;
    };

    using StatusCallback = std::function<void(const std::string&, const std::string&, const std::string&)>;

    class DeviceMonitor {
    public:
        DeviceMonitor();
        ~DeviceMonitor();

        void Start(StatusCallback callback);
        void Stop();
        void SetTargets(const std::vector<std::string>& ips);

    private:
        void MonitorLoop();

        StatusCallback m_callback;
        std::atomic<bool> m_running;
        std::thread m_thread;
        
        std::vector<MonitoredDevice> m_targets;
        std::mutex m_mutex;
    };
}