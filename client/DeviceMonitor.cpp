#include "DeviceMonitor.hpp"
#include "SnmpClient.hpp" // Integrated Real SNMP
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <tins/tins.h>
#include <iomanip>
#include <sstream>

namespace net_ops::client
{

    DeviceMonitor::DeviceMonitor() : m_running(false)
    {
    }

    DeviceMonitor::~DeviceMonitor()
    {
        Stop();
    }

    void DeviceMonitor::SetTargets(const std::vector<std::string> &ips)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Preserve state of existing devices
        std::vector<MonitoredDevice> new_targets;
        new_targets.reserve(ips.size());

        for (const auto& ip : ips) {
            bool found = false;
            for (const auto& existing : m_targets) {
                if (existing.ip == ip) {
                    new_targets.push_back(existing);
                    found = true;
                    break;
                }
            }
            if (!found) {
                MonitoredDevice dev;
                dev.ip = ip;
                dev.is_online = false;
                dev.last_snmp_check = std::chrono::steady_clock::time_point::min();
                new_targets.push_back(dev);
            }
        }
        m_targets = new_targets;
    }

    void DeviceMonitor::Start(StatusCallback callback)
    {
        if (m_running)
            return;
        m_running = true;
        m_callback = callback;
        m_thread = std::thread(&DeviceMonitor::MonitorLoop, this);
    }

    void DeviceMonitor::Stop()
    {
        m_running = false;
        if (m_thread.joinable())
            m_thread.join();
    }

    // RETURNS: Latency in ms, or -1.0 if unreachable
    double PingLatency(const std::string &target_ip)
    {
        try
        {
            Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
            
            Tins::SnifferConfiguration config;
            config.set_promisc_mode(false);
            config.set_filter("icmp[icmptype] == icmp-echoreply and src host " + target_ip);
            config.set_timeout(1); // 1s timeout

            Tins::Sniffer sniffer(iface.name(), config);

            Tins::IP ip = Tins::IP(target_ip) / Tins::ICMP();
            Tins::ICMP &icmp = ip.rfind_pdu<Tins::ICMP>();
            icmp.type(Tins::ICMP::ECHO_REQUEST);
            icmp.id(0x1337);
            icmp.sequence(1);

            Tins::PacketSender sender;
            
            auto start = std::chrono::high_resolution_clock::now();
            sender.send(ip);

            auto packet = sniffer.next_packet();
            auto end = std::chrono::high_resolution_clock::now();
            
            if (packet) {
                std::chrono::duration<double, std::milli> elapsed = end - start;
                return elapsed.count();
            }
        }
        catch (...)
        {
            return -1.0;
        }
        return -1.0;
    }

    // Helper to format Uptime TimeTicks (1/100th sec) to string
    std::string FormatUptime(long ticks) {
        if (ticks < 0) return "";
        long seconds = ticks / 100;
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        std::stringstream ss;
        ss << hours << "h " << minutes << "m";
        return ss.str();
    }

    void DeviceMonitor::MonitorLoop()
    {
        SnmpClient snmpClient;

        while (m_running)
        {
            std::vector<MonitoredDevice> devices_copy;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                devices_copy = m_targets;
            }

            for (auto &dev : devices_copy)
            {
                if (!m_running) break;

                double latency = PingLatency(dev.ip);
                bool online = (latency >= 0.0);
                
                std::string status = online ? "Online" : "Offline";
                std::stringstream desc;

                if (online) {
                    desc << std::fixed << std::setprecision(1) << "Lat: " << latency << "ms";

                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - dev.last_snmp_check).count();
                    
                    if (elapsed > 30) {
                        long ticks = snmpClient.GetUptime(dev.ip, "public");
                        if (ticks > 0) {
                            dev.cached_uptime = FormatUptime(ticks);
                        } else {
                            dev.cached_uptime = "";
                        }
                        
                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            for(auto &d : m_targets) {
                                if(d.ip == dev.ip) {
                                    d.last_snmp_check = now;
                                    d.cached_uptime = dev.cached_uptime;
                                    break;
                                }
                            }
                        }
                    }

                    if (!dev.cached_uptime.empty()) {
                        desc << " | Up: " << dev.cached_uptime;
                    }
                }

                if (m_callback) {
                    m_callback(dev.ip, status, desc.str());
                }
            }

            // Sleep 2s
            for (int i = 0; i < 20; ++i) {
                if (!m_running) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
}
