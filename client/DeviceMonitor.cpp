#include "DeviceMonitor.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <tins/tins.h>


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
        m_targets.clear();
        m_targets.reserve(ips.size());
        
        for (const auto& ip : ips) {
            MonitoredDevice dev;
            dev.ip = ip;
            dev.is_online = false;
            dev.last_snmp_check = std::chrono::steady_clock::now();
            m_targets.push_back(dev);
        }
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

    bool Ping(const std::string &target_ip)
    {
        try
        {
            Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
            
            Tins::SnifferConfiguration config;
            config.set_promisc_mode(false);
            config.set_filter("icmp[icmptype] == icmp-echoreply and src host " + target_ip);
            config.set_timeout(1);

            Tins::Sniffer sniffer(iface.name(), config);

            Tins::IP ip = Tins::IP(target_ip) / Tins::ICMP();
            Tins::ICMP &icmp = ip.rfind_pdu<Tins::ICMP>();
            icmp.type(Tins::ICMP::ECHO_REQUEST);
            icmp.id(0x1337);
            icmp.sequence(1);

            Tins::PacketSender sender;
            sender.send(ip);

            auto packet = sniffer.next_packet();
            
            if (packet) {
                return true;
            }
        }
        catch (const std::exception &)
        {
            return false;
        }
        return false;
    }

    void DeviceMonitor::MonitorLoop()
    {
        while (m_running)
        {
            std::vector<MonitoredDevice> devices;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                devices = m_targets;
            }

            for (auto &dev : devices)
            {
                if (!m_running) break;

                bool online = Ping(dev.ip);
                std::string status = online ? "Online" : "Offline";
                std::string desc = "Monitoring via libtins";

                if (m_callback)
                {
                    m_callback(dev.ip, status, desc);
                }
            }

            for (int i = 0; i < 50; ++i) {
                if (!m_running) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
}