#include "NetworkCore.hpp"
#include "DatabaseManager.hpp"
#include "Worker.hpp"
#include <iostream>

int main() {
    auto& db = net_ops::server::DatabaseManager::GetInstance();
    
    if (!db.Initialize("server_data.db")) {
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
    catch(const std::exception& e)
    {
        std::cerr << "Fatal Server Error: " << e.what() << '\n';
        return -1;
    }

    return 0;
}