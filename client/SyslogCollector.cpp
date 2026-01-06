#include "SyslogCollector.hpp"
#include <iostream>
#include <cstring>      
#include <unistd.h>     
#include <sys/socket.h> 
#include <arpa/inet.h>  

namespace net_ops::client {

    SyslogCollector::SyslogCollector() : m_sockfd(-1), m_port(5140), m_running(false) {
        std::memset(m_buffer, 0, sizeof(m_buffer));
    }

    SyslogCollector::~SyslogCollector() {
        Stop();
    }

    bool SyslogCollector::Start(int port, LogCallback callback) {
        if (m_running) return false;
        
        m_port = port;
        m_callback = callback;

        m_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sockfd < 0) {
            std::cerr << "[Agent] Failed to create UDP socket.\n";
            return false;
        }

        struct sockaddr_in server_addr;
        std::memset(&server_addr, 0, sizeof(server_addr));
        
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(m_port);

        if (bind(m_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "[Agent] Failed to bind to UDP port " << m_port << ".\n";
            close(m_sockfd);
            return false;
        }

        m_running = true;
        m_worker_thread = std::thread(&SyslogCollector::ListenerLoop, this);
        
        std::cout << "[Agent] Syslog Listener started on port " << m_port << "\n";
        return true;
    }

    void SyslogCollector::Stop() {
        if (!m_running) return;
        m_running = false;
        if (m_sockfd >= 0) close(m_sockfd);
        if (m_worker_thread.joinable()) m_worker_thread.join();
    }

    void SyslogCollector::ListenerLoop() {
        struct sockaddr_in client_addr;
        socklen_t client_len;
        ssize_t bytes_received;
        char sender_ip[INET_ADDRSTRLEN];

        while (m_running) {
            std::memset(&client_addr, 0, sizeof(client_addr));
            client_len = sizeof(client_addr);

            bytes_received = recvfrom(m_sockfd, m_buffer, sizeof(m_buffer) - 1, 0, (struct sockaddr*)&client_addr, &client_len);

            if (bytes_received > 0) {
                m_buffer[bytes_received] = '\0';
                inet_ntop(AF_INET, &(client_addr.sin_addr), sender_ip, INET_ADDRSTRLEN);

                // Call the Lambda in main.cpp
                if (m_callback) {
                    m_callback(std::string(sender_ip), std::string(m_buffer));
                }
            } 
        }
    }
}