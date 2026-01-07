#include "SyslogCollector.hpp"
#include <iostream>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <fstream>

namespace net_ops::client
{
    SyslogCollector::SyslogCollector(const std::string &logPath)
        : m_path(logPath), m_running(false), m_callback(nullptr),
          m_udp_fd(-1), m_inotify_fd(-1)
    {
    }

    SyslogCollector::~SyslogCollector()
    {
        Stop();
    }

    void SyslogCollector::Start(int port, LogCallback callback)
    {
        if (m_running)
            return;

        m_callback = callback;
        m_running = true;

        m_udp_worker = std::thread(&SyslogCollector::ReceiveLoop, this, port);
        m_file_worker = std::thread(&SyslogCollector::FileMonitorLoop, this);

        std::cout << "[SyslogCollector] Agent monitoring UDP:" << port << " and file:" << m_path << "\n";
    }

    void SyslogCollector::Stop()
    {
        m_running = false;

        if (m_udp_fd != -1)
        {
            shutdown(m_udp_fd, SHUT_RDWR);
            close(m_udp_fd);
            m_udp_fd = -1;
        }

        if (m_inotify_fd != -1)
        {
            close(m_inotify_fd);
            m_inotify_fd = -1;
        }

        if (m_udp_worker.joinable())
            m_udp_worker.join();
        if (m_file_worker.joinable())
            m_file_worker.join();
    }

    void SyslogCollector::ReceiveLoop(int port)
    {
        m_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_udp_fd < 0)
            return;

        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(m_udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            close(m_udp_fd);
            return;
        }

        char buffer[4096];
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        while (m_running)
        {
            ssize_t received = recvfrom(m_udp_fd, buffer, sizeof(buffer) - 1, 0,
                                        (struct sockaddr *)&client_addr, &addr_len);
            if (received > 0 && m_callback)
            {
                buffer[received] = '\0';
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, INET_ADDRSTRLEN);

                m_callback(std::string(ip_str), std::string(buffer));
            }
        }
    }

    void SyslogCollector::FileMonitorLoop()
    {
        m_inotify_fd = inotify_init();
        if (m_inotify_fd < 0)
            return;

        int wd = inotify_add_watch(m_inotify_fd, m_path.c_str(), IN_MODIFY);
        if (wd < 0)
        {
            close(m_inotify_fd);
            return;
        }

        std::ifstream file(m_path);
        file.seekg(0, std::ios::end);

        char event_buf[4096];
        while (m_running)
        {
            ssize_t length = read(m_inotify_fd, event_buf, sizeof(event_buf));
            if (length < 0)
                break;

            if (m_running)
            {
                std::string line;
                file.clear();
                while (std::getline(file, line))
                {
                    if (!line.empty() && m_callback)
                    {
                        m_callback("127.0.0.1", line);
                    }
                }
            }
        }
        inotify_rm_watch(m_inotify_fd, wd);
    }
}