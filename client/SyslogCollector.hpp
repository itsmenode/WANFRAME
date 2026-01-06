#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <netinet/in.h>

namespace net_ops::client {

    using LogCallback = std::function<void(const std::string&, const std::string&)>;

    class SyslogCollector {
    public:
        SyslogCollector();
        ~SyslogCollector();

        bool Start(int port, LogCallback callback);
        void Stop();

    private:
        void ListenerLoop();

        int m_sockfd;
        int m_port;
        std::atomic<bool> m_running;
        std::thread m_worker_thread;
        char m_buffer[4096];
        
        LogCallback m_callback; 
    };
}