#include <net/ethernet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdint.h>
#include <iostream>

#include "linked_list.h"
#include "packet_structure.h"
#include "packet_filter.h"


#define ETHER_HEADER_SIZE   14
#define LIST_SIZE   1000

enum {arp=0, icmp, igmp, tcp, udp};

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


int main(int argc, char* argv[])
{
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

//    char * My_ip_str = argv[2];
//    uint8_t My_ip[4];
//    inet_pton(AF_INET, My_ip_str, My_ip);

    Node * BlackList;
    BlackList = new Node();
//    BlackList = new Node(My_ip);


    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true)
    {

        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        printf("---------Packet Classification----------\n");
        int p = Packet_Classification(packet, BlackList);

        if(p==arp)
            printf("arp\n");
        else if (p==icmp)
            printf("icmp\n");
        else if (p==igmp)
            printf("igmp\n");
        else if (p==tcp)
        {
            printf("tcp\n");

            if(TCP_PACKET_Classification(packet, BlackList) == -1)  // if drop packet;
            {
                printf("drop\n");
                continue;
            }

        }
        else if (p==udp)
            printf("udp\n");
        else if (p==-1)
            printf("drop\n");
        else
        {
            continue;
        }

        //send packet to my_server

    }

    pcap_close(handle);

    return 0;
}

