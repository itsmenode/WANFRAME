#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "Worker.hpp"
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

static net_ops::server::NetworkCore *g_network_core = nullptr;
static std::atomic<bool> *g_syslog_running = nullptr;
void SignalHandler(int s)
{
    if (g_network_core)
        g_network_core->Stop();
    if (g_syslog_running)
        g_syslog_running->store(false);
}

void Daemonize()
{
    if (fork() > 0)
        exit(0);
    setsid();
    if (fork() > 0)
        exit(0);
    int fd = open("/dev/null", O_RDWR);
    if (fd != -1)
    {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);
    }
}

int ResolveSyslogPort(int argc, char *argv[])
{
    int port = 514;
    const char *env_port = std::getenv("WANFRAME_SYSLOG_PORT");
    if (env_port && *env_port)
    {
        int parsed = std::atoi(env_port);
        if (parsed > 0 && parsed <= 65535)
            port = parsed;
    }

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--syslog-port" && i + 1 < argc)
        {
            int parsed = std::atoi(argv[i + 1]);
            if (parsed > 0 && parsed <= 65535)
                port = parsed;
            ++i;
        }
        else if (arg.rfind("--syslog-port=", 0) == 0)
        {
            int parsed = std::atoi(arg.substr(std::strlen("--syslog-port=")).c_str());
            if (parsed > 0 && parsed <= 65535)
                port = parsed;
        }
    }
    return port;
}

std::thread StartSyslogListener(std::atomic<bool> &running, int port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw std::runtime_error("Failed to create syslog UDP socket");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        close(sock);
        throw std::runtime_error("Failed to bind syslog UDP socket");
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1)
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return std::thread([sock, &running]()
                       {
                           char buffer[2048];
                           while (running.load())
                           {
                               sockaddr_in src{};
                               socklen_t srclen = sizeof(src);
                               ssize_t received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                                                           reinterpret_cast<sockaddr *>(&src), &srclen);
                               if (received > 0)
                               {
                                   buffer[received] = '\0';
                                   char ip[INET_ADDRSTRLEN] = {0};
                                   inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
                                   net_ops::server::DatabaseManager::GetInstance().SaveLog(ip, buffer);
                               }
                               else
                               {
                                   std::this_thread::sleep_for(std::chrono::milliseconds(50));
                               }
                           }
                           close(sock);
                       });
}

int main(int argc, char *argv[])
{
    bool daemon = false;
    auto &db = net_ops::server::DatabaseManager::GetInstance();
    int syslogPort = ResolveSyslogPort(argc, argv);
    std::atomic<bool> syslogRunning{true};
    g_syslog_running = &syslogRunning;

    for (int i = 1; i < argc; ++i)
    {
        if (std::string(argv[i]) == "-d")
            daemon = true;
    }

    if (!db.Initialize("server_data.db"))
        return 1;

    std::thread syslogThread;
    try
    {
        if (daemon)
        {
            std::cout << "[System] Starting daemon mode...\n";
            Daemonize();
        }
        else
        {
            std::cout << "[System] Interactive mode. Ctrl+C to stop.\n";
        }

        net_ops::server::Worker worker;
        worker.Start();
        net_ops::server::NetworkCore server(8080, &worker);
        worker.SetNetworkCore(&server);
        g_network_core = &server;

        signal(SIGINT, SignalHandler);
        signal(SIGTERM, SignalHandler);
        server.Init();

        syslogThread = StartSyslogListener(syslogRunning, syslogPort);

        server.Run();
        syslogRunning.store(false);
        if (syslogThread.joinable())
            syslogThread.join();
        worker.Stop();
        db.Shutdown();
    }
    catch (const std::exception &e)
    {
        syslogRunning.store(false);
        if (syslogThread.joinable())
            syslogThread.join();
        std::cerr << "[Fatal] " << e.what() << "\n";
        db.Shutdown();
        return 1;
    }
    return 0;
}
