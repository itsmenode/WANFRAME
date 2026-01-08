#include "Scanner.hpp"
#include <tins/tins.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <unistd.h>
#include <fstream>
#include <sstream>

namespace net_ops::client
{
    bool IsRoot() {
        return geteuid() == 0;
    }

    std::vector<ScannedHost> ReadSystemArpTable(const std::string& targetIface) {
        std::vector<ScannedHost> results;
        std::ifstream arpFile("/proc/net/arp");
        if (!arpFile.is_open()) return results;

        std::string line;
        std::getline(arpFile, line);

        while (std::getline(arpFile, line)) {
            std::stringstream ss(line);
            std::string ip, hw_type, flags, mac, mask, dev;
            ss >> ip >> hw_type >> flags >> mac >> mask >> dev;

            if (dev == targetIface && mac != "00:00:00:00:00:00") {
                results.push_back({ip, mac, "Known Neighbor"});
            }
        }
        return results;
    }

    std::vector<ScannedHost> NetworkScanner::ScanLocalNetwork()
    {
        std::vector<ScannedHost> foundHosts;
        std::mutex resultsMutex;

        if (!IsRoot()) {
            std::cerr << "[Scanner] ERROR: Not running as root. ARP scan will fail.\n";
            return foundHosts;
        }

        try
        {
            Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
            Tins::NetworkInterface::Info info = iface.info();
            
            std::cout << "[Scanner] Interface: " << iface.name() 
                      << " | IP: " << info.ip_addr 
                      << " | MAC: " << info.hw_addr << "\n";

            auto cached = ReadSystemArpTable(iface.name());
            for (const auto& h : cached) {
                foundHosts.push_back(h);
            }
            std::cout << "[Scanner] Loaded " << cached.size() << " cached neighbors.\n";

            Tins::SnifferConfiguration config;
            config.set_promisc_mode(false);
            config.set_filter("arp and arp[6:2] == 2 and not src host " + info.ip_addr.to_string());
            config.set_timeout(1); 

            Tins::Sniffer sniffer(iface.name(), config);
            Tins::PacketSender sender;

            std::vector<std::string> targets;
            std::string baseIp = info.ip_addr.to_string();
            size_t lastDot = baseIp.find_last_of('.');
            if (lastDot != std::string::npos) {
                std::string prefix = baseIp.substr(0, lastDot + 1);
                
                for (int i = 1; i < 255; ++i) {
                    std::string target = prefix + std::to_string(i);
                    if (target != baseIp) {
                        targets.push_back(target);
                    }
                }
            }

            std::atomic<bool> stopSniffer(false);
            std::thread snifferThread([&]() {
                while (!stopSniffer) {
                    Tins::PDU* pdu = sniffer.next_packet();
                    if (pdu) {
                        const Tins::ARP& arp = pdu->rfind_pdu<Tins::ARP>();
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        
                        std::string ip = arp.sender_ip_addr().to_string();
                        std::string mac = arp.sender_hw_addr().to_string();

                        bool exists = false;
                        for(const auto& h : foundHosts) {
                            if (h.ip == ip) { exists = true; break; }
                        }

                        if (!exists) {
                            foundHosts.push_back({ip, mac, "Active Scan"});
                            std::cout << "[Scanner] Found NEW: " << ip << " (" << mac << ")\n";
                        }
                        delete pdu;
                    }
                }
            });

            std::cout << "[Scanner] Scanning " << targets.size() << " hosts (" 
                      << targets.front() << " - " << targets.back() << ")...\n";

            int sentCount = 0;
            for (const auto& targetIpStr : targets) {
                try {
                    Tins::IPv4Address targetIp(targetIpStr);
                    Tins::EthernetII eth = Tins::EthernetII("ff:ff:ff:ff:ff:ff", info.hw_addr) / 
                                           Tins::ARP(targetIp, info.ip_addr, Tins::HWAddress<6>("00:00:00:00:00:00"), info.hw_addr);
                    sender.send(eth, iface);
                    sentCount++;
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(5)); 
                } catch (const std::exception& ex) {
                    std::cerr << "[Scanner] Packet Send Error on " << targetIpStr << ": " << ex.what() << "\n";
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(2));
            
            stopSniffer = true;
            snifferThread.join();
        }
        catch (const std::exception& e)
        {
            std::cerr << "[Scanner] Critical Error: " << e.what() << "\n";
        }

        return foundHosts;
    }
}