#include <iostream>
#include <string>
#include <mutex>
#include <vector>
#include "ClientNetwork.hpp"
#include "Scanner.hpp"
#include "SyslogCollector.hpp"
#include "DeviceMonitor.hpp"

std::mutex g_net_lock;

net_ops::client::DeviceMonitor g_monitor;

std::string GetInput(const std::string& prompt) {
    std::cout << prompt;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

void DashboardLoop(net_ops::client::ClientNetwork& client) {
    bool in_dashboard = true;
    while (in_dashboard) {
        std::cout << "\n--- DASHBOARD ---\n";
        std::cout << "1. Create Group\n";
        std::cout << "2. List My Groups\n";
        std::cout << "3. Add Member to Group\n";
        std::cout << "4. Add Device (Manual)\n";
        std::cout << "5. List All Devices\n";
        std::cout << "6. Auto-Scan & Monitor\n"; 
        std::cout << "7. View Device Logs\n";
        std::cout << "8. Logout\n";
        std::cout << "Select: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            std::string name = GetInput("Enter Group Name: ");
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendCreateGroup(name);
            client.ReceiveResponse();
        } 
        else if (choice == "2") {
            std::cout << "Requesting Group List...\n";
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendListGroups();
            client.ReceiveResponse();
        } 
        else if (choice == "3") {
            std::string idStr = GetInput("Enter Group ID: ");
            std::string userToAdd = GetInput("Enter Username to Invite: ");
            
            try {
                int gid = std::stoi(idStr);
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendAddMember(gid, userToAdd);
                client.ReceiveResponse();
            } catch (...) {
                std::cout << "Invalid Group ID format.\n";
            }
        }
        else if (choice == "4") {
            std::string name = GetInput("Device Name: ");
            std::string ip = GetInput("IP Address: ");
            std::string gidStr = GetInput("Group ID (0 for none): ");
            
            try {
                int gid = std::stoi(gidStr);
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendAddDevice(name, ip, gid);
                client.ReceiveResponse();
            } catch (...) {
                std::cout << "Invalid Group ID. Using 0.\n";
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendAddDevice(name, ip, 0);
                client.ReceiveResponse();
            }
        }
        else if (choice == "5") {
            std::cout << "Fetching Device Inventory...\n";
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendListDevices();
            client.ReceiveResponse();
        }
        else if (choice == "6") {
            std::cout << "Starting Auto-Discovery...\n";
            
            auto hosts = net_ops::client::NetworkScanner::ScanLocalNetwork();
            
            if (hosts.empty()) {
                std::cout << "No OTHER devices found.\n";
            } else {
                std::cout << "Found " << hosts.size() << " devices. Uploading & Monitoring...\n";
                
                std::vector<std::string> monitor_ips;

                {
                    std::lock_guard<std::mutex> lock(g_net_lock);
                    for (const auto& host : hosts) {
                        client.SendAddDevice(host.name, host.ip, 0);
                        client.ReceiveResponse();
                        
                        monitor_ips.push_back(host.ip);
                    }
                }
                
                g_monitor.SetTargets(monitor_ips);
                std::cout << "Active Monitoring enabled for these devices.\n";
            }
        }
        else if (choice == "7") {
            std::cout << "--- Device List ---\n";
            {
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendListDevices();
                client.ReceiveResponse();
            }

            std::string idStr = GetInput("Enter Device ID to view logs: ");
            try {
                int devId = std::stoi(idStr);
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendFetchLogs(devId);
                client.ReceiveResponse();
            } catch (...) {
                std::cout << "Invalid ID.\n";
            }
        }
        else if (choice == "8") {
            in_dashboard = false;
        } 
        else {
            std::cout << "Invalid option.\n";
        }
    }
}

int main() {
    net_ops::client::ClientNetwork client("127.0.0.1", 8080);

    if (!client.Connect()) {
        std::cerr << "Failed to connect to server. Is it running?\n";
        return -1;
    }

    bool running = true;
    while (running) {
        std::cout << "\n--- MAIN MENU ---\n";
        std::cout << "1. Login\n";
        std::cout << "2. Register\n";
        std::cout << "3. Exit\n";
        std::cout << "Select: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            std::string u = GetInput("Username: ");
            std::string p = GetInput("Password: ");
            
            bool loginSuccess = false;
            {
                std::lock_guard<std::mutex> lock(g_net_lock);
                client.SendLogin(u, p);
                loginSuccess = client.ReceiveResponse();
            }
            
            if (loginSuccess) {
                std::cout << "\n>>> Login Successful! <<<\n";

                net_ops::client::SyslogCollector syslogAgent;
                bool agentStarted = syslogAgent.Start(5140, [&](const std::string& ip, const std::string& msg) {
                    std::lock_guard<std::mutex> lock(g_net_lock);
                    client.SendLogUpload(ip, msg);
                });

                if (!agentStarted) {
                    std::cerr << "[Warning] Syslog Agent failed to start (Port 5140 busy?)\n";
                }

                g_monitor.Start([&](const std::string& ip, const std::string& status, const std::string& desc) {
                    std::lock_guard<std::mutex> lock(g_net_lock);
                    client.SendStatusUpdate(ip, status, desc);
                });

                DashboardLoop(client);

                g_monitor.Stop();
                syslogAgent.Stop();
                std::cout << "[System] Services stopped.\n";
                
            } else {
                std::cout << "\n>>> Login Failed. <<<\n";
            }
        } 
        else if (choice == "2") {
            std::string u = GetInput("New Username: ");
            std::string p = GetInput("New Password: ");
            
            std::lock_guard<std::mutex> lock(g_net_lock);
            client.SendRegister(u, p);
            client.ReceiveResponse();
        } 
        else if (choice == "3") {
            running = false;
        }
        else {
            std::cout << "Invalid option.\n";
        }
    }

    client.Disconnect();
    return 0;
}