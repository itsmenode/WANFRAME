#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "Worker.hpp"
#include <iostream>

int main() {
    auto& db = net_ops::server::DatabaseManager::GetInstance();
    
    if (!db.Initialize("test_db.sqlite")) {
        std::cerr << "Failed to init DB\n";
        return -1;
    }

    std::cout << "--- Running Database Test ---\n";
    
    std::vector<uint8_t> dummy_hash = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> dummy_salt = {0x11, 0x22};

    if (db.CreateUser("test_admin", dummy_hash, dummy_salt)) {
        std::cout << "[SUCCESS] Created user 'test_admin'\n";
    } else {
        std::cout << "[INFO] User 'test_admin' probably already exists\n";
    }

    auto user = db.GetUserByName("test_admin");
    if (user.has_value()) {
        std::cout << "[SUCCESS] Found user: " << user->username 
                  << " (ID: " << user->id << ")\n";
    } else {
        std::cerr << "[FAIL] Could not find 'test_admin'\n";
    }
    std::cout << "--- Test Complete ---\n";

    try
    {
        net_ops::server::Worker worker;
        worker.Start();

        net_ops::server::NetworkCore server(8080, &worker);
        
        worker.SetNetworkCore(&server);

        server.Init();
        server.Run();

        worker.Stop();
    }
    catch(const std::exception& e)
    {
        std::cerr << "Fatal Server Error: " << e.what() << '\n';
        return -1;
    }

    return 0;
}