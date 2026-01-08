#include "SyslogCollector.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>

namespace net_ops::client
{
    SyslogCollector::SyslogCollector(const std::string &logPath, int port)
        : m_logPath(logPath), m_port(port), m_running(false)
    {
    }

    SyslogCollector::~SyslogCollector() { Stop(); }

    void SyslogCollector::SetPort(int port)
    {
        m_port = port;
    }

    void SyslogCollector::Start(DataCallback callback)
    {
        if (m_running)
            return;
        if (m_port <= 0)
        {
            std::cerr << "[Syslog] Invalid port configured.\n";
            return;
        }
        m_running = true;

        m_worker = std::thread([this, callback]()
                               {
            int port = m_port;
            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd < 0) {
                std::cerr << "[Syslog] Failed to create socket\n";
                m_running = false;
                return;
            }

            struct sockaddr_in servaddr;
            std::memset(&servaddr, 0, sizeof(servaddr));
            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = INADDR_ANY;
            servaddr.sin_port = htons(port);

            if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
                std::cerr << "[Syslog] Bind failed on port " << port << " (Permission denied?)\n";
                close(sockfd);
                m_running = false;
                return;
            }

            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

            std::cout << "[Syslog] Listening on UDP port " << port << "\n";

            char buffer[4096];
            struct sockaddr_in cliaddr;
            socklen_t len = sizeof(cliaddr);

            while (m_running) {
                int n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&cliaddr, &len);
                
                if (n > 0) {
                    buffer[n] = '\0';
                    std::string raw(buffer);
                    DataRecord record;
                    record.type = DataRecordType::Syslog;
                    record.ip = inet_ntoa(cliaddr.sin_addr);

                    if (raw[0] == '<') {
                        size_t endPri = raw.find('>');
                        if (endPri != std::string::npos) {
                            record.priority = std::stoi(raw.substr(1, endPri - 1));
                            record.facility = record.priority / 8;
                            record.severity = record.priority % 8;
            
                            record.message = raw.substr(endPri + 1);
                        }
                    } else {
                        record.message = raw;
                    }

                    if (callback) callback(record);
                }
            }

            close(sockfd);
            std::cout << "[Syslog] Stopped.\n";
        });
    }

    void SyslogCollector::Stop()
    {
        m_running = false;
        if (m_worker.joinable())
            m_worker.join();
    }
}
