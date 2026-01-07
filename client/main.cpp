#include <iostream>
#include <string>
#include <mutex>
#include <vector>
#include <limits>
#include "ClientNetwork.hpp"
#include "Scanner.hpp"
#include "SyslogCollector.hpp"
#include "DeviceMonitor.hpp"

std::mutex g_net_lock;
net_ops::client::DeviceMonitor g_monitor;

std::string GetInput(const std::string &prompt)
{
    std::cout << prompt;
    std::string line;
    std::getline(std::cin, line);

    if (line.empty())
    {
        std::getline(std::cin, line);
    }
    return line;
}

void DashboardLoop(net_ops::client::ClientNetwork &client)
{
    bool in_dashboard = true;
    while (in_dashboard)
    {
        std::cout << "\n--- DASHBOARD ---\n";
        std::cout << "1. Create Group\n2. List My Groups\n3. Add Member to Group\n";
        std::cout << "4. Add Device (Manual)\n5. List All Devices\n6. Auto-Scan & Monitor\n";
        std::cout << "7. View Device Logs\n8. Logout\nSelect: ";

        std::string choice;
        if (!(std::cin >> choice)) break;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == "8")
        {
            std::cout << "[System] Performing network logout...\n";
            {
                std::lock_guard<std::mutex> lock(g_net_lock);
                if (client.SendLogout()) {
                    client.ReceiveResponse(); 
                }
            }
            in_dashboard = false;
        }
        else if (choice == "1")
        {
            std::string name = GetInput("Enter Group Name: ");
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendCreateGroup(name);
            client.ReceiveResponse();
        }
        else if (choice == "2")
        {
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendListGroups();
            client.ReceiveResponse();
        }
        else if (choice == "3")
        {
            std::string idStr = GetInput("Enter Group ID: ");
            std::string userToAdd = GetInput("Enter Username to Invite: ");
            try {
                int gid = std::stoi(idStr);
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendAddMember(gid, userToAdd);
                client.ReceiveResponse();
            } catch (...) { std::cout << "Invalid Group ID.\n"; }
        }
        else if (choice == "4")
        {
            std::string name = GetInput("Device Name: ");
            std::string ip = GetInput("IP Address: ");
            std::string gidStr = GetInput("Group ID (0 for none): ");
            try {
                int gid = gidStr.empty() ? 0 : std::stoi(gidStr);
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendAddDevice(name, ip, "00:00:00:00:00:00", gid);
                client.ReceiveResponse();
            } catch (...) { std::cout << "Invalid Group ID.\n"; }
        }
        else if (choice == "5")
        {
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendListDevices();
            client.ReceiveResponse();
        }
        else if (choice == "6")
        {
            std::cout << "\n--- AUTO-SCAN INITIATED ---\n";
            auto hosts = net_ops::client::NetworkScanner::ScanLocalNetwork();
            if (hosts.empty()) {
                std::vector<std::string> monitor_ips = {"127.0.0.1"};
                g_monitor.SetTargets(monitor_ips);
            } else {
                std::lock_guard<std::mutex> lock(g_net_lock);
                for (const auto &host : hosts) {
                    client.SendAddDevice(host.name, host.ip, host.mac, 0);
                    client.ReceiveResponse();
                }
            }
        }
        else if (choice == "7")
        {
            {
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendListDevices();
                client.ReceiveResponse();
            }
            std::cout << "Enter Device ID to view logs: ";
            int devId = -1;
            if (std::cin >> devId) {
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendFetchLogs(devId);
                client.ReceiveResponse();
            } else {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            }
        }
        else
        {
            std::cout << "Invalid option.\n";
        }
    }
}

int main()
{
    net_ops::client::ClientNetwork client("127.0.0.1", 8080);
    if (!client.Connect())
    {
        std::cerr << "Failed to connect to server.\n";
        return -1;
    }

    bool running = true;
    while (running)
    {
        std::cout << "\n--- MAIN MENU ---\n";
        std::cout << "1. Login\n2. Register\n3. Exit\nSelect: ";
        std::string choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == "1")
        {
            std::string u = GetInput("Username: ");
            std::string p = GetInput("Password: ");

            bool loginSuccess = false;
            {
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendLogin(u, p);
                loginSuccess = client.ReceiveResponse();
            }

            if (loginSuccess)
            {
                std::cout << "\n>>> Login Successful! <<<\n";

                net_ops::client::SyslogCollector syslogAgent;
                syslogAgent.Start(5140, [&](const std::string &ip, const std::string &msg)
                                  {
                    std::lock_guard<std::mutex> lock(g_net_lock);
                    client.SendLogUpload(ip, msg); });

                g_monitor.Start([&](const std::string &ip, const std::string &status, const std::string &desc)
                                {
                    std::lock_guard<std::mutex> lock(g_net_lock);
                    client.SendStatusUpdate(ip, status, desc); });

                DashboardLoop(client);

                g_monitor.Stop();
                syslogAgent.Stop();
                std::cout << "[System] Logged out. Returning to Main Menu.\n";
            }
            else
            {
                std::cout << "\n>>> Login Failed. <<<\n";
            }
        }
        else if (choice == "2")
        {
            std::string u = GetInput("New Username: ");
            std::string p = GetInput("New Password: ");
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendRegister(u, p);
            client.ReceiveResponse();
        }
        else if (choice == "3")
        {
            running = false;
        }
    }
    client.Disconnect();
    return 0;
}