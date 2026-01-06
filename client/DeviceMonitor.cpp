#include "DeviceMonitor.hpp"
#include "Scanner.hpp" 
#include "SnmpClient.hpp"
#include <iostream>
#include <chrono>

namespace net_ops::client {

    DeviceMonitor::DeviceMonitor(ClientNetwork& network) 
        : m_network(network), m_running(false) {}

    DeviceMonitor::~DeviceMonitor() {
        Stop();
    }

    void DeviceMonitor::SetTargets(const std::vector<std::string>& ips) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_targets.clear();
        for(const auto& ip : ips) {
            m_targets.push_back({ip, false});
        }
        std::cout << "[Monitor] Watching " << ips.size() << " devices.\n";
    }

    void DeviceMonitor::Start() {
        if (m_running) return;
        m_running = true;
        m_thread = std::thread(&DeviceMonitor::MonitorLoop, this);
        std::cout << "[Monitor] Background thread started.\n";
    }

    void DeviceMonitor::Stop() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
    }

    void DeviceMonitor::MonitorLoop() {
        SnmpClient snmp;

        while (m_running) {
            std::vector<std::string> ips_to_check;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                for(const auto& t : m_targets) ips_to_check.push_back(t.ip);
            }

            if (ips_to_check.empty()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            for (const auto& ip : ips_to_check) {
                if (!m_running) break;

                bool alive = NetworkScanner::Ping(ip);
                std::string status = alive ? "ONLINE" : "OFFLINE";
                std::string desc = "";

                if (alive) {
                    DeviceStats stats = snmp.QueryDevice(ip, "public");
                    if (stats.success) {
                        desc = stats.description;
                    }
                }
                 m_network.SendStatusUpdate(ip, status, desc);
            }

            for(int i=0; i<30; i++) {
                if(!m_running) break;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }
}