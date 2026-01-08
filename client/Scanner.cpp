#include "Scanner.hpp"
#include <tins/tins.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <unistd.h>

namespace net_ops::client
{
    bool IsRoot() {
        return geteuid() == 0;
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
            
            Tins::IPv4Address myIp = info.ip_addr;
            Tins::IPv4Address netmask = info.netmask;
            
            std::cout << "[Scanner] Interface: " << iface.name() 
                      << " | IP: " << myIp 
                      << " | Mask: " << netmask 
                      << " | HW: " << info.hw_addr << "\n";

            Tins::SnifferConfiguration config;
            config.set_promisc_mode(false);
            config.set_filter("arp and arp[6:2] == 2");
            config.set_timeout(1);

            Tins::Sniffer sniffer(iface.name(), config);
            Tins::PacketSender sender;

            uint32_t ipInt = (uint32_t)myIp;
            uint32_t maskInt = (uint32_t)netmask;
            uint32_t networkInt = ipInt & maskInt;
            
            std::vector<Tins::IPv4Address> targets;
            for (int i = 1; i < 255; ++i) {
                uint32_t targetInt = networkInt | Tins::Endian::host_to_be(i); 
                if (targetInt == ipInt) continue;
                targets.push_back(Tins::IPv4Address(targetInt));
            }

            std::atomic<bool> stopSniffer(false);
            
            std::thread snifferThread([&]() {
                while (!stopSniffer) {
                    Tins::PDU* pdu = sniffer.next_packet();
                    
                    if (pdu) {
                        const Tins::ARP& arp = pdu->rfind_pdu<Tins::ARP>();
                        if (arp.sender_ip_addr() != myIp) {
                            std::lock_guard<std::mutex> lock(resultsMutex);
                            
                            bool exists = false;
                            for(const auto& h : foundHosts) {
                                if (h.ip == arp.sender_ip_addr().to_string()) {
                                    exists = true; break;
                                }
                            }

                            if (!exists) {
                                ScannedHost host;
                                host.ip = arp.sender_ip_addr().to_string();
                                host.mac = arp.sender_hw_addr().to_string();
                                host.name = "Unknown"; 
                                foundHosts.push_back(host);
                                std::cout << "[Scanner] Found Device: " << host.ip << "\n";
                            }
                        }
                        delete pdu;
                    }
                }
            });

            std::cout << "[Scanner] Sending " << targets.size() << " ARP requests...\n";
            for (const auto& targetIp : targets) {
                try {
                    Tins::EthernetII eth = Tins::EthernetII("ff:ff:ff:ff:ff:ff", info.hw_addr) / 
                                           Tins::ARP(targetIp, myIp, Tins::HWAddress<6>("00:00:00:00:00:00"), info.hw_addr);
                    sender.send(eth, iface);
                    std::this_thread::sleep_for(std::chrono::microseconds(200));
                } catch (...) {}
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