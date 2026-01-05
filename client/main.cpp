#include <iostream>
#include <string>
#include "ClientNetwork.hpp"
#include "Scanner.hpp"

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
        std::cout << "6. Auto-Scan Network\n";
        std::cout << "7. Logout\n";
        std::cout << "Select: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            std::string name = GetInput("Enter Group Name: ");
            client.SendCreateGroup(name);
            client.ReceiveResponse();
        } 
        else if (choice == "2") {
            std::cout << "Requesting Group List...\n";
            client.SendListGroups();
            client.ReceiveResponse();
        } 
        else if (choice == "3") {
            std::string idStr = GetInput("Enter Group ID: ");
            std::string userToAdd = GetInput("Enter Username to Invite: ");
            
            try {
                int gid = std::stoi(idStr);
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
                client.SendAddDevice(name, ip, gid);
                client.ReceiveResponse();
            } catch (...) {
                std::cout << "Invalid Group ID. Using 0.\n";
                client.SendAddDevice(name, ip, 0);
                client.ReceiveResponse();
            }
        }
        else if (choice == "5") {
            std::cout << "Fetching Device Inventory...\n";
            client.SendListDevices();
            client.ReceiveResponse();
        }
        else if (choice == "6") {
            std::cout << "Starting Auto-Discovery...\n";
            
            auto hosts = net_ops::client::NetworkScanner::ScanLocalNetwork();
            
            if (hosts.empty()) {
                std::cout << "No OTHER devices found on your network.\n";
            } else {
                std::cout << "Uploading " << hosts.size() << " devices to Server...\n";
                for (const auto& host : hosts) {
                    client.SendAddDevice(host.name, host.ip, 0);
                    client.ReceiveResponse(); 
                }
                std::cout << "Upload Complete.\n";
            }
        }
        else if (choice == "7") {
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
            
            client.SendLogin(u, p);
            
            if (client.ReceiveResponse()) {
                std::cout << "\n>>> Entering Dashboard... <<<\n";
                DashboardLoop(client);
            } else {
                std::cout << "\n>>> Login Failed. <<<\n";
            }
        } 
        else if (choice == "2") {
            std::string u = GetInput("New Username: ");
            std::string p = GetInput("New Password: ");
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