#include <net/ethernet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdint.h>
#include <iostream>

#include "packet_filter.h"
#include "linked_list.h"
#include "packet_structure.h"


enum {arp=0, icmp, igmp, tcp, udp};


int Packet_Classification(const u_char* packet, Node * BlackList)
{

    Ethernet * eth_H = (Ethernet *)(packet);
    int eth_SIZE = 14;

    if(htons(eth_H->type) == ETHERTYPE_ARP)
        return arp;
    if(htons(eth_H->type) != ETHERTYPE_IP)
        return -1;

    Ip * ip_H = (Ip *)(packet + eth_SIZE);

    if(FindBlackList(BlackList, ip_H->s_ip))
    {
        printf("FindBlackList\n");
        return -1;
    }

    if(ip_H->protocol == IPPROTO_ICMP)
        return icmp;
    if(ip_H->protocol == IPPROTO_IGMP)
        return igmp;
    if(ip_H->protocol == IPPROTO_TCP)
        return tcp;
    if(ip_H->protocol == IPPROTO_UDP)
        return udp;

    return -1;
}

int TCP_PACKET_Classification(const u_char* packet, Node * BlackList)
{

    Ethernet * eth_H = (Ethernet *)(packet);
    int eth_SIZE = 14;

    Ip * ip_H = (Ip *)(packet + eth_SIZE);
    int ip_SIZE = (ip_H->VHL & 0x0F) * 4;
    int total_SIZE = ntohs(ip_H->Total_LEN);

    Tcp * tcp_h = (Tcp *)(packet + eth_SIZE + ip_SIZE);
    int tcp_SIZE = ((tcp_h->OFF & 0xF0) >> 4) * 4;

    u_char * payload = (u_char*)(packet + eth_SIZE + ip_SIZE + tcp_SIZE);
    int payload_len = (total_SIZE) - (ip_SIZE + tcp_SIZE);

    uint8_t flag=(tcp_h->flag & 0x3F);

    /*************Tsunami Flood Attack************/

    if(flag!=0x08 && flag!=0x10 && flag!= 0x18 && (eth_SIZE + total_SIZE) > 94) // PSH, ACK, PSH + ACK, Packet SIZE
    {
        AddBlackList(BlackList, ip_H->s_ip);
        printf("%02X\n", flag);
        printf("%d\n", total_SIZE + eth_SIZE);
        printf("AddBlackList\n");
        return -1;
    }
    /*********************************************/


    //    printf("flag = ");
    //    if(flag == 0x01)
    //        printf("FIN\n");
    //    else if (flag == 0x02)
    //        printf("SYN\n");
    //    else if (flag == 0x04)
    //        printf("RST\n");
    //    else if (flag == 0x08)
    //        printf("PSH\n");
    //    else if (flag == 0x10)
    //        printf("ACK\n");
    //    else if (flag == 0x20)
    //        printf("RST\n");
    //    else printf("?\n");


    return 1;
}
