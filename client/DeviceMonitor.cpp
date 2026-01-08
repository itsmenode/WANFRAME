#include "DeviceMonitor.hpp"
#include "SnmpClient.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <tins/tins.h>
#include <iomanip>
#include <sstream>

namespace net_ops::client
{
    DeviceMonitor::DeviceMonitor() : m_running(false) {}
    DeviceMonitor::~DeviceMonitor() { Stop(); }

    void DeviceMonitor::SetTargets(const std::vector<std::string> &ips) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<MonitoredDevice> new_targets;
        new_targets.reserve(ips.size());
        for (const auto& ip : ips) {
            bool found = false;
            for (const auto& existing : m_targets) {
                if (existing.ip == ip) {
                    new_targets.push_back(existing);
                    found = true; break;
                }
            }
            if (!found) {
                MonitoredDevice dev; dev.ip = ip; dev.is_online = false;
                dev.last_snmp_check = std::chrono::steady_clock::time_point::min();
                new_targets.push_back(dev);
            }
        }
        m_targets = new_targets;
    }

    void DeviceMonitor::Start(StatusCallback callback) {
        if (m_running) return;
        m_running = true;
        m_callback = callback;
        m_thread = std::thread(&DeviceMonitor::MonitorLoop, this);
    }

    void DeviceMonitor::Stop() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
    }

    double PingLatency(const std::string &target_ip) {
        try {
            Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
            Tins::SnifferConfiguration config;
            config.set_filter("icmp[icmptype] == icmp-echoreply and src host " + target_ip);
            config.set_timeout(1);
            Tins::Sniffer sniffer(iface.name(), config);
            Tins::PacketSender sender;
            
            Tins::IP ip = Tins::IP(target_ip) / Tins::ICMP();
            ip.rfind_pdu<Tins::ICMP>().type(Tins::ICMP::ECHO_REQUEST);
            ip.rfind_pdu<Tins::ICMP>().sequence(1);

            auto start = std::chrono::high_resolution_clock::now();
            sender.send(ip);
            auto packet = sniffer.next_packet();
            auto end = std::chrono::high_resolution_clock::now();
            
            if (packet) return std::chrono::duration<double, std::milli>(end - start).count();
        } catch (...) { return -1.0; }
        return -1.0;
    }

    std::string FormatUptime(long ticks) {
        if (ticks < 0) return "";
        long seconds = ticks / 100;
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        return std::to_string(hours) + "h " + std::to_string(minutes) + "m";
    }

    void DeviceMonitor::MonitorLoop() {
        SnmpClient snmp;
        while (m_running) {
            std::vector<MonitoredDevice> copy;
            { std::lock_guard<std::mutex> lock(m_mutex); copy = m_targets; }

            for (auto &dev : copy) {
                if (!m_running) break;
                double lat = PingLatency(dev.ip);
                bool online = (lat >= 0);
                std::string status = online ? "Online" : "Offline";
                std::stringstream info;

                if (online) {
                    info << std::fixed << std::setprecision(1) << "Lat:" << lat << "ms";
                    
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - dev.last_snmp_check).count() > 30) {
                        long up = snmp.GetUptime(dev.ip);
                        dev.cached_uptime = (up > 0) ? FormatUptime(up) : "";
                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            for(auto &d : m_targets) if(d.ip == dev.ip) {
                                d.last_snmp_check = now; d.cached_uptime = dev.cached_uptime; break;
                            }
                        }
                    }
                    if (!dev.cached_uptime.empty()) info << " Up:" << dev.cached_uptime;
                }
                if (m_callback) m_callback(dev.ip, status, info.str());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        }
    }
}