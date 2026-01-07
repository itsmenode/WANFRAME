#include "SyslogCollector.hpp"
#include "ClientNetwork.hpp"
#include <sys/inotify.h>
#include <unistd.h>
#include <fstream>
#include <iostream>

extern net_ops::client::ClientNetwork g_client;

void net_ops::client::SyslogCollector::MonitorLoop()
{
    int fd = inotify_init();
    if (fd < 0)
        return;

    int wd = inotify_add_watch(fd, m_path.c_str(), IN_MODIFY);

    std::ifstream file(m_path);
    file.seekg(0, std::ios::end);

    char buffer[4096];
    while (m_running)
    {
        int length = read(fd, buffer, sizeof(buffer));
        if (length > 0)
        {
            std::string line;
            while (std::getline(file, line))
            {
                if (!line.empty())
                {
                }
            }
            file.clear();
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
}