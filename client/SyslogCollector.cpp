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
    SyslogCollector::SyslogCollector(const std::string &logPath)
        : m_logPath(logPath), m_running(false)
    {
    }

    SyslogCollector::~SyslogCollector() { Stop(); }

    void SyslogCollector::Start(int port, LogCallback callback)
    {
        if (m_running) return;
        m_running = true;

        m_worker = std::thread([this, port, callback]()
        {
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
            
            int boundPort = 514;
            servaddr.sin_port = htons(boundPort);
            
            if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
                boundPort = port;
                servaddr.sin_port = htons(boundPort);
                if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
                    std::cerr << "[Syslog] Bind failed on port " << boundPort << "\n";
                    close(sockfd);
                    m_running = false;
                    return;
                }
            }

            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

            std::cout << "[Syslog] Listening on UDP port " << boundPort << "\n";

            char buffer[4096];
            struct sockaddr_in cliaddr;
            socklen_t len = sizeof(cliaddr);

            while (m_running) {
                int n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&cliaddr, &len);
                
                if (n > 0) {
                    buffer[n] = '\0';
                    std::string sourceIp = inet_ntoa(cliaddr.sin_addr);
                    std::string message(buffer);

                    if (callback) {
                        callback(sourceIp, message);
                    }
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