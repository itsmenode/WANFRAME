#include "SyslogCollector.hpp"
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <filesystem>
#include <vector>

namespace net_ops::client
{
    SyslogCollector::SyslogCollector(const std::string &logPath)
        : m_logPath(logPath), m_running(false)
    {
    }

    SyslogCollector::~SyslogCollector() { Stop(); }

    void SyslogCollector::Start(int port, LogCallback callback)
    {
        if (!std::filesystem::exists(m_logPath))
        {
            if (std::filesystem::exists("/var/log/messages"))
            {
                std::cout << "[Syslog] /var/log/syslog not found, using /var/log/messages\n";
                m_logPath = "/var/log/messages";
            }
            else
            {
                std::cerr << "[Syslog] ERROR: No syslog file found at " << m_logPath << " or /var/log/messages.\n";
            }
        }

        m_running = true;
        m_worker = std::thread([this, callback]()
                               {
            std::ifstream file(m_logPath);
            
            if (file.is_open()) {
                file.seekg(0, std::ios::end);
                std::streampos length = file.tellg();
                std::streampos startPos = (length > 2048) ? (length - (std::streampos)2048) : 0;
                file.seekg(startPos);
                
                std::string line;
                if (startPos != 0) std::getline(file, line);
                
                while(std::getline(file, line)) {
                     if (!line.empty() && callback) {
                         callback("Localhost", line);
                     }
                }
                file.clear(); 
            }

            while (m_running) {
                if (!file.is_open()) {
                    file.open(m_logPath);
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }

                std::string line;
                while (std::getline(file, line)) {
                    if (!line.empty() && callback) {
                         callback("Localhost", line);
                    }
                }
                
                if (file.eof()) {
                    file.clear();
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            } });
    }

    void SyslogCollector::Stop()
    {
        m_running = false;
        if (m_worker.joinable())
            m_worker.join();
    }
}