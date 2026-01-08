#include "Scanner.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <tins/tins.h>

namespace net_ops::client
{
    using namespace Tins;

    std::vector<ScannedHost> NetworkScanner::ScanLocalNetwork() {
        std::vector<ScannedHost> hosts;
        std::mutex mtx;

        try {
            NetworkInterface iface = NetworkInterface::default_interface();
            NetworkInterface::Info info = iface.info();
            
            IPv4Address my_ip = info.ip_addr;
            IPv4Address netmask = info.netmask;
            HWAddress<6> my_mac = info.hw_addr;

            std::cout << "[Scanner] Interface: " << iface.name() 
                      << " IP: " << my_ip 
                      << " MAC: " << my_mac << std::endl;

            IPv4Range range = IPv4Range::from_mask(my_ip, netmask);

            std::thread snifferThread([&]() {
                Sniffer sniffer(iface.name());
                sniffer.set_filter("arp and arp[6:2] == 2");
                
                auto start = std::chrono::steady_clock::now();
                
                sniffer.sniff_loop([&](PDU &pdu) {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() > 2) {
                        return false;
                    }

                    const ARP &arp = pdu.rfind_pdu<ARP>();
                    std::string ip = arp.sender_ip_addr().to_string();
                    std::string mac = arp.sender_hw_addr().to_string();

                    if (ip == my_ip.to_string()) return true;

                    std::lock_guard<std::mutex> lock(mtx);
                    
                    bool found = false;
                    for(const auto& h : hosts) if(h.ip == ip) found = true;
                    
                    if(!found) {
                        hosts.push_back({ip, mac, "Discovered Device", true});
                    }
                    return true;
                });
            });

            PacketSender sender;
            for (const auto &addr : range) {
                if (addr == my_ip) continue; 

                EthernetII eth = EthernetII(HWAddress<6>("ff:ff:ff:ff:ff:ff"), my_mac) /
                                 ARP::make_arp_request(addr, my_ip, my_mac);
                
                try {
                    sender.send(eth, iface);
                } catch (...) {
                }
            }

            if(snifferThread.joinable()) snifferThread.join();

            hosts.push_back({my_ip.to_string(), my_mac.to_string(), "My Computer (Local)", true});

        } catch (std::exception &ex) {
            std::cerr << "[Scanner] Error: " << ex.what() << std::endl;
        }

        return hosts;
    }
    
    std::string NetworkScanner::GetLocalIPAddress() {
        try {
            return NetworkInterface::default_interface().info().ip_addr.to_string();
        } catch(...) {
            return "127.0.0.1";
        }
    }
    
    std::string NetworkScanner::GetSubnetFromIP(const std::string &ip) { return ""; }
    bool NetworkScanner::Ping(const std::string &ip) { return false; }
    std::string NetworkScanner::GetMacFromArp(const std::string &target_ip) { return ""; }
}