#include <iostream>
#include <string>
#include "ClientNetwork.hpp"

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
        std::cout << "4. Logout\n";
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
                std::cout << "Invalid Group ID format. Please enter a number.\n";
            }
        }
        else if (choice == "4") {
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
                std::cout << "\n>>> Login Failed. Access Denied. <<<\n";
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