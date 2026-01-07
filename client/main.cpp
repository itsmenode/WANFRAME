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

std::string GetInput(const std::string &prompt)
{
    std::cout << prompt;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

void DashboardLoop(net_ops::client::ClientNetwork &client)
{
    bool in_dashboard = true;
    while (in_dashboard)
    {
        std::cout << "\n--- DASHBOARD ---\n";
        std::cout << "1. Add Device (Manual)\n";
        std::cout << "2. List All Devices\n";
        std::cout << "3. Auto-Scan & Monitor\n";
        std::cout << "4. View Device Logs\n";
        std::cout << "5. Logout\n";
        std::cout << "Select: ";

        std::string choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == "5") {
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendLogout();
            in_dashboard = false;
        }
        else if (choice == "1") {
            std::string name = GetInput("Device Name: ");
            std::string ip = GetInput("IP Address: ");
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendAddDevice(name, ip, "00:00:00:00:00:00");
        }
        else if (choice == "2") {
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendListDevices();
            client.ReceiveResponse();
        }
        else if (choice == "3") {
            auto hosts = net_ops::client::NetworkScanner::ScanLocalNetwork();
            std::lock_guard<std::mutex> lock(g_net_lock);
            for (const auto &host : hosts) client.SendAddDevice(host.name, host.ip, host.mac);
        }
        else if (choice == "4") {
            int devId = std::stoi(GetInput("Enter Device ID: "));
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendFetchLogs(devId);
            client.ReceiveResponse();
        }
    }
}

int main()
{
    net_ops::client::ClientNetwork client("127.0.0.1", 8080);
    if (!client.Connect()) return -1;

    bool running = true;
    while (running)
    {
        std::cout << "\n1. Login\n2. Register\n3. Exit\nSelect: ";
        std::string choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == "1") {
            std::string u = GetInput("Username: ");
            std::string p = GetInput("Password: ");
            std::lock_guard<std::mutex> lock(g_net_lock);
            if (client.SendLogin(u, p) && client.ReceiveResponse()) DashboardLoop(client);
        }
        else if (choice == "2") {
            std::string u = GetInput("New Username: ");
            std::string p = GetInput("New Password: ");
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendRegister(u, p);
            client.ReceiveResponse();
        }
        else if (choice == "3") running = false;
    }
    client.Disconnect();
    return 0;
}