#include "DeviceMonitor.hpp"
#include "Scanner.hpp" 
#include "SnmpClient.hpp"
#include <iostream>
#include <algorithm>

namespace net_ops::client {

    DeviceMonitor::DeviceMonitor() : m_running(false) {}

    DeviceMonitor::~DeviceMonitor() {
        Stop();
    }

    void DeviceMonitor::SetTargets(const std::vector<std::string>& ips) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_targets.clear();
        for(const auto& ip : ips) {
            MonitoredDevice dev;
            dev.ip = ip;
            dev.is_online = false;
            dev.last_snmp_check = std::chrono::steady_clock::time_point::min();
            m_targets.push_back(dev);
        }
        std::cout << "[Monitor] Watching " << ips.size() << " devices.\n";
    }

    void DeviceMonitor::Start(StatusCallback callback) {
        if (m_running) return;
        m_callback = callback;
        m_running = true;
        m_thread = std::thread(&DeviceMonitor::MonitorLoop, this);
        std::cout << "[Monitor] Background thread started.\n";
    }

    void DeviceMonitor::Stop() {
        m_running = false;
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    void DeviceMonitor::MonitorLoop() {
        SnmpClient snmp;

        while (m_running) {
            std::vector<MonitoredDevice> local_targets;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                local_targets = m_targets;
            }

            if (local_targets.empty()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            auto now = std::chrono::steady_clock::now();

            for (auto& dev : local_targets) {
                if (!m_running) break;

                bool alive = NetworkScanner::Ping(dev.ip);
                std::string status = alive ? "ONLINE" : "OFFLINE";
                std::string desc = "";

                bool time_for_snmp = (now - dev.last_snmp_check) > std::chrono::seconds(60);

                if (alive && time_for_snmp) {
                    DeviceStats stats = snmp.QueryDevice(dev.ip, "public");
                    
                    if (stats.success) {
                        desc = stats.description;
                    }
                    
                    dev.last_snmp_check = now;
                    
                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        for(auto& t : m_targets) {
                            if(t.ip == dev.ip) t.last_snmp_check = now;
                        }
                    }
                }

                if (m_callback) {
                    m_callback(dev.ip, status, desc);
                }
            }

            for(int i=0; i<5; i++) {
                if(!m_running) break;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }
}