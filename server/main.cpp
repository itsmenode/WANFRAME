#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "Worker.hpp"
#include <iostream>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

void Daemonize()
{
    pid_t pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    umask(0);
    if (chdir("/") < 0)
        exit(EXIT_FAILURE);

    int devNull = open("/dev/null", O_RDWR);
    if (devNull != -1)
    {
        dup2(devNull, STDIN_FILENO);
        dup2(devNull, STDOUT_FILENO);
        dup2(devNull, STDERR_FILENO);
        close(devNull);
    }
}

int main()
{

    auto &db = net_ops::server::DatabaseManager::GetInstance();

    if (!db.Initialize("server_data.db"))
    {
        std::cerr << "Failed to init DB\n";
        return -1;
    }

    std::cout << "[System] Database initialized successfully.\n";

    try
    {
        net_ops::server::Worker worker;
        worker.Start();

        net_ops::server::NetworkCore server(8080, &worker);
        worker.SetNetworkCore(&server);

        std::cout << "[System] Server listening on port 8080...\n";
        server.Init();
        server.Run();

        worker.Stop();
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal Server Error: " << e.what() << '\n';
        return -1;
    }

    return 0;
}