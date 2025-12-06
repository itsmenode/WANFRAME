#include "NetworkCore.hpp"
#include <iostream>

int main() {
    net_ops::server::NetworkCore server(8080);

    try
    {
        server.Init();
        server.Run();
    }
    catch(const std::exception& e)
    {
        std::cerr << "Fatal Server Error: " << e.what() << '\n';
        return -1;
    }

    return 0;
}