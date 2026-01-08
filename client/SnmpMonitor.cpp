#include "SnmpMonitor.hpp"
#include <utility>

namespace net_ops::client
{
    SnmpMonitor::SnmpMonitor(std::chrono::milliseconds interval)
        : m_running(false), m_interval(interval)
    {
    }

    SnmpMonitor::~SnmpMonitor()
    {
        Stop();
    }

    void SnmpMonitor::SetTargets(const std::vector<std::string> &ips)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_targets = ips;
    }

    void SnmpMonitor::Start(DataCallback callback)
    {
        if (m_running)
            return;
        m_running = true;
        m_callback = std::move(callback);
        m_thread = std::thread(&SnmpMonitor::MonitorLoop, this);
    }

    void SnmpMonitor::Stop()
    {
        m_running = false;
        if (m_thread.joinable())
            m_thread.join();
    }

    void SnmpMonitor::MonitorLoop()
    {
        while (m_running)
        {
            std::vector<std::string> targets;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                targets = m_targets;
            }

            for (const auto &ip : targets)
            {
                if (!m_running)
                    break;

                DeviceStats stats = m_client.QueryDevice(ip);

                DataRecord record;
                record.type = DataRecordType::SnmpStatus;
                record.ip = ip;
                record.status = stats.success ? "SNMP" : "SNMP_FAIL";
                record.info = stats.success ? stats.description : "SNMP timeout";

                if (m_callback)
                {
                    m_callback(record);
                }
            }

            SleepInterval();
        }
    }

    void SnmpMonitor::SleepInterval()
    {
        const auto step = std::chrono::milliseconds(100);
        const auto steps = static_cast<int>(m_interval / step);

        for (int i = 0; i < steps; ++i)
        {
            if (!m_running)
                return;
            std::this_thread::sleep_for(step);
        }
    }
}
