#include <iostream>
#include <string>
#include <limits>
#include "ClientNetwork.hpp"

void ClearInput() {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

int main() {
    std::cout << "--- WANFRAME Client ---\n";
    std::cout << "Connecting to 127.0.0.1:8080...\n";

    net_ops::client::ClientNetwork client("127.0.0.1", 8080);
    
    if (!client.Connect()) {
        std::cerr << "[Fatal] Could not connect to server. Is it running?\n";
        return -1;
    }

    bool running = true;
    while (running) {
        std::cout << "\n[MENU]\n";
        std::cout << "1. Login\n";
        std::cout << "2. Register\n";
        std::cout << "3. Exit\n";
        std::cout << "Select option: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            ClearInput();
            continue;
        }
        ClearInput();

        std::string username, password;

        if (choice == 1 || choice == 2) {
            std::cout << "Username: ";
            std::getline(std::cin, username);
            std::cout << "Password: ";
            std::getline(std::cin, password);
        }

        switch (choice) {
            case 1:
                if (client.SendLogin(username, password)) {
                    std::cout << "[Client] >> Login Request Sent. Waiting for response...\n";
                    client.ReceiveResponse(); 
                } else {
                    std::cerr << "[Client] Failed to send data.\n";
                }
                break;

            case 2:
                if (client.SendRegister(username, password)) {
                    std::cout << "[Client] >> Register Request Sent. Waiting for response...\n";
                    client.ReceiveResponse();
                } else {
                    std::cerr << "[Client] Failed to send data.\n";
                }
                break;

            case 3:
                running = false;
                break;

            default:
                std::cout << "Invalid option.\n";
                break;
        }
    }

    client.Disconnect();
    return 0;
}