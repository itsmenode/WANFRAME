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
#include <arpa/inet.h> 
#include <set>

namespace net_ops::client
{
    bool IsRoot() {
        return geteuid() == 0;
    }

    uint32_t IpToInt(const Tins::IPv4Address& ip) {
        return static_cast<uint32_t>(ip);
    }

    Tins::IPv4Address IntToIp(uint32_t ip) {
        return Tins::IPv4Address(ip);
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
                results.push_back({ip, mac, "Known Neighbor (Cache)"});
            }
        }
        return results;
    }

    std::vector<ScannedHost> NetworkScanner::ScanLocalNetwork()
    {
        std::vector<ScannedHost> foundHosts;
        std::set<std::string> seenIps;
        std::mutex resultsMutex;

        if (!IsRoot()) {
            std::cerr << "[Scanner] ERROR: Not running as root. Scan aborted.\n";
            return foundHosts;
        }

        try
        {
            Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
            Tins::NetworkInterface::Info info = iface.info();
            
            {
                std::lock_guard<std::mutex> lock(resultsMutex);
                foundHosts.push_back({info.ip_addr.to_string(), info.hw_addr.to_string(), "Localhost (Me)"});
                seenIps.insert(info.ip_addr.to_string());
            }

            std::set<std::string> targetIps;
            
            uint32_t ip_val = IpToInt(info.ip_addr);
            uint32_t mask_val = IpToInt(info.netmask);
            uint32_t network_val = ip_val & mask_val;
            uint32_t broadcast_val = network_val | (~mask_val);

            uint32_t start_scan = network_val + 1;
            uint32_t end_scan = broadcast_val;

            if ((end_scan - start_scan) > 512) {
                start_scan = 0;
            }

            if (start_scan != 0) {
                for (uint32_t t = start_scan; t < end_scan; ++t) {
                    if (t == ip_val) continue;
                    targetIps.insert(IntToIp(t).to_string());
                }
            } else {
                std::string base = info.ip_addr.to_string();
                std::string prefix = base.substr(0, base.find_last_of('.') + 1);
                for (int i = 1; i < 255; ++i) {
                    std::string t_str = prefix + std::to_string(i);
                    if (t_str != base) targetIps.insert(t_str);
                }
            }

            
            auto cached = ReadSystemArpTable(iface.name());
            for (const auto& h : cached) {
                 if (h.ip != info.ip_addr.to_string()) {
                     targetIps.insert(h.ip);
                 }
            }

            Tins::SnifferConfiguration config;
            config.set_promisc_mode(false);
            config.set_filter("arp or (icmp and icmp[icmptype] == icmp-echoreply)");
            config.set_timeout(100);

            Tins::Sniffer sniffer(iface.name(), config);
            Tins::PacketSender sender;
            std::atomic<bool> stopSniffer(false);
            
            std::thread snifferThread([&]() {
                while (!stopSniffer) {
                    try {
                        Tins::PDU* pdu = sniffer.next_packet();
                        if (pdu) {
                            std::string found_ip, found_mac, found_type;
                            bool valid = false;

                            const Tins::ARP* arp = pdu->find_pdu<Tins::ARP>();
                            if (arp && arp->opcode() == Tins::ARP::REPLY) {
                                found_ip = arp->sender_ip_addr().to_string();
                                found_mac = arp->sender_hw_addr().to_string();
                                found_type = "ARP Reply";
                                valid = true;
                            }
                            
                            const Tins::IP* ip = pdu->find_pdu<Tins::IP>();
                            if (!valid && ip) {
                                const Tins::ICMP* icmp = pdu->find_pdu<Tins::ICMP>();
                                if (icmp && icmp->type() == Tins::ICMP::ECHO_REPLY) {
                                    found_ip = ip->src_addr().to_string();
                                    found_mac = "Unknown";
                                    const Tins::EthernetII* eth = pdu->find_pdu<Tins::EthernetII>();
                                    if (eth) found_mac = eth->src_addr().to_string();
                                    found_type = "ICMP Reply";
                                    valid = true;
                                }
                            }

                            if (valid) {
                                std::lock_guard<std::mutex> lock(resultsMutex);
                                if (seenIps.find(found_ip) == seenIps.end()) {
                                    foundHosts.push_back({found_ip, found_mac, found_type});
                                    seenIps.insert(found_ip);
                                }
                            }
                            delete pdu;
                        }
                    } catch(...) { }
                }
            });

            for (const auto& targetIpStr : targetIps) {
                try {
                    Tins::IPv4Address targetIp(targetIpStr);
                    
                    Tins::EthernetII eth = Tins::EthernetII("ff:ff:ff:ff:ff:ff", info.hw_addr) / 
                        Tins::ARP(targetIp, info.ip_addr, Tins::HWAddress<6>("00:00:00:00:00:00"), info.hw_addr);
                    sender.send(eth, iface);
                    
                    std::this_thread::sleep_for(std::chrono::microseconds(300));

                    Tins::EthernetII eth2 = Tins::EthernetII("ff:ff:ff:ff:ff:ff", info.hw_addr) /
                        Tins::IP(targetIp, info.ip_addr) / Tins::ICMP();
                    sender.send(eth2, iface);
                    
                    std::this_thread::sleep_for(std::chrono::microseconds(300));
                } catch (...) {}
            }

            std::this_thread::sleep_for(std::chrono::seconds(2));
            stopSniffer = true;
            
            try {
                Tins::EthernetII eth = Tins::EthernetII(info.hw_addr, info.hw_addr) / Tins::IP(info.ip_addr, info.ip_addr);
                sender.send(eth, iface);
            } catch(...) {}

            if (snifferThread.joinable()) snifferThread.join();
        }
        catch (const std::exception& e)
        {
            std::cerr << "[Scanner] Exception: " << e.what() << "\n";
        }

        return foundHosts;
    }
}