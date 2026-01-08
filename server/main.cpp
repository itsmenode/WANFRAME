#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "Worker.hpp"
#include <iostream>
#include <csignal>
#include <unistd.h>
#include <fcntl.h>

static net_ops::server::NetworkCore *g_network_core = nullptr;
void SignalHandler(int s)
{
    if (g_network_core)
        g_network_core->Stop();
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

int main(int argc, char *argv[])
{
    bool daemon = (argc > 1 && std::string(argv[1]) == "-d");
    auto &db = net_ops::server::DatabaseManager::GetInstance();

    if (!db.Initialize("server_data.db"))
        return 1;

    try
    {
        net_ops::server::Worker worker;
        worker.Start();
        net_ops::server::NetworkCore server(8080, &worker);
        worker.SetNetworkCore(&server);
        g_network_core = &server;

        signal(SIGINT, SignalHandler);
        signal(SIGTERM, SignalHandler);
        server.Init();

        if (daemon)
        {
            std::cout << "[System] Starting daemon mode...\n";
            Daemonize();
        }
        else
        {
            std::cout << "[System] Interactive mode. Ctrl+C to stop.\n";
        }

        server.Run();
        worker.Stop();
        db.Shutdown();
    }
    catch (const std::exception &e)
    {
        std::cerr << "[Fatal] " << e.what() << "\n";
        return 1;
    }
    return 0;
}