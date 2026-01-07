#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "Worker.hpp"

#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdlib>

static net_ops::server::NetworkCore *g_network_core = nullptr;

void SignalHandler(int signum)
{
    if (g_network_core)
        g_network_core->Stop();
}

void Daemonize()
{
    pid_t pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    umask(0);

    int fd = open("/dev/null", O_RDWR);
    if (fd != -1)
    {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }
}

int main(int argc, char *argv[])
{
    bool run_as_daemon = (argc > 1 && std::string(argv[1]) == "-d");

    auto &db = net_ops::server::DatabaseManager::GetInstance();
    if (!db.Initialize("server_data.db"))
        return EXIT_FAILURE;

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

        if (run_as_daemon)
        {
            std::cout << "[System] Entering daemon mode (check logs for errors)...\n";
            Daemonize();
        }
        else
        {
            std::cout << "[System] Starting in interactive mode. Press Ctrl+C to stop.\n";
        }

        server.Run();

        worker.Stop();
        db.Shutdown();
    }
    catch (const std::exception &e)
    {
        std::cerr << "[Fatal] " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}