#include "SyslogCollector.hpp"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace net_ops::client
{
    SyslogCollector::SyslogCollector(const std::string &logPath)
        : m_path(logPath), m_running(false), m_callback(nullptr), m_server_fd(-1)
    {
    }

    SyslogCollector::~SyslogCollector()
    {
        Stop();
    }

    void SyslogCollector::Start(int port, LogCallback callback)
    {
        if (m_running) return;

        m_callback = callback;
        m_running = true;
        m_worker = std::thread(&SyslogCollector::ReceiveLoop, this, port);
        std::cout << "[SyslogCollector] UDP Relay listening on port " << port << "...\n";
    }

    void SyslogCollector::Stop()
    {
        m_running = false;
        if (m_server_fd != -1)
        {
            shutdown(m_server_fd, SHUT_RDWR);
            close(m_server_fd);
            m_server_fd = -1;
        }

        if (m_worker.joinable())
        {
            m_worker.join();
        }
    }

    void SyslogCollector::ReceiveLoop(int port)
    {
        m_server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_server_fd < 0)
        {
            std::cerr << "[SyslogCollector] Socket creation failed\n";
            return;
        }

        int opt = 1;
        setsockopt(m_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in address;
        std::memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(m_server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        {
            std::cerr << "[SyslogCollector] Bind failed on port " << port << "\n";
            close(m_server_fd);
            m_server_fd = -1;
            return;
        }

        char buffer[4096];
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        while (m_running)
        {
            ssize_t received = recvfrom(m_server_fd, buffer, sizeof(buffer) - 1, 0,
                                        (struct sockaddr *)&client_addr, &addr_len);

            if (received > 0 && m_callback)
            {
                buffer[received] = '\0';
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
                
                m_callback(std::string(ip_str), std::string(buffer));
            }
            else if (received < 0 && m_running)
            {
                break;
            }
        }
    }
}