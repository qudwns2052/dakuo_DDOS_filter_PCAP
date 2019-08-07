#include "ifctl.h"
#include "packet_filter.h"
#include "packet_structure.h"
#include <arpa/inet.h>
#include <iostream>
#include <net/ethernet.h>
#include <pcap.h>
#include <set>
#include <stdint.h>

//void print_info(Ethernet * e, Ip * ip, Tcp * tcp)
//{
//    printf("d_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", e->d_mac[0],e->d_mac[1],e->d_mac[2],e->d_mac[3],e->d_mac[4],e->d_mac[5]);
//    printf("s_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", e->s_mac[0],e->s_mac[1],e->s_mac[2],e->s_mac[3],e->s_mac[4],e->s_mac[5]);
//    printf("s_ip = %u.%u.%u.%u\n", ip->s_ip[0], ip->s_ip[1], ip->s_ip[2], ip->s_ip[3]);
//    printf("d_ip = %u.%u.%u.%u\n", ip->d_ip[0], ip->d_ip[1], ip->d_ip[2], ip->d_ip[3]);
//    printf("s_port = %d\n", htons(tcp->s_port));
//    printf("d_port = %d\n", htons(tcp->d_port));
//}

//u_int16_t get_checksum(u_int16_t* buf, int nwords)
//{
//    u_int32_t sum;
//    for(sum=0; nwords>0; nwords--) sum += *buf++;
//    sum = (sum >> 16) + (sum & 0xffff);
//    sum += (sum >> 16);
//    return (u_int16_t)(~sum);
//}

int main(int argc, char *argv[])
{
    // FastIO: If Activated, DO NOT USE printf/scanf!!
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);

    // Usage
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return -1;
    }

    // Get Device Name
    const char *dev = argv[1];

    // Get My IP
    in_addr_t myIP = get_my_ip(dev);

    // PCAP Open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return -1;
    }

    std::set<in_addr_t> blacklist;
    while (true) {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
            continue;
        if (res < 0)
            break;

        std::cout << "---------Packet Classification----------\n";
        switch (packet_classification(packet)) {
        case PacketClass::TCP:
            if (detect_attack(packet, blacklist, myIP) != AttackClass::ACCEPT) // if drop packet;
            {
                std::cout << "Drop\n";
                continue;
            }
            break;
        case PacketClass::ARP:
        case PacketClass::ICMP:
        case PacketClass::IGMP:
        case PacketClass::UDP:
        case PacketClass::IP:
        case PacketClass::UNCLASSIFIED:
            break;
        }

        // send packet to my_server
    }

    pcap_close(handle);

    return 0;
}
