#include <net/ethernet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdint.h>
#include <iostream>
#include <time.h>

#include "packet_filter.h"
#include "linked_list.h"
#include "packet_structure.h"


enum {arp=0, icmp, igmp, tcp, udp};


int Packet_Classification(const u_char* packet, Node * BlackList)
{
    /**************Packet Parsing********************/

    Ethernet * eth_H = (Ethernet *)(packet);
    int eth_SIZE = 14;

    if(htons(eth_H->type) == ETHERTYPE_ARP)
        return arp;
    if(htons(eth_H->type) != ETHERTYPE_IP)
        return -1;

    Ip * ip_H = (Ip *)(packet + eth_SIZE);

    /************************************************/

    /************Check Ip in Black List**************/

    if(BlackList->FindBlackList(BlackList, ip_H->s_ip))
    {
        printf("FindBlackList\n");
        return -1;
    }

    /************************************************/


    /******************Land Attack*******************/

    if(!memcmp(ip_H->d_ip,ip_H->s_ip,4))
    {
        BlackList->AddBlackList(BlackList, ip_H->s_ip);
        printf("Land Attack\n");
        printf("AddBlackList\n");
        return -1;
    }
    /************************************************/


    /************Packet Classification***************/

    if(ip_H->protocol == IPPROTO_ICMP)
        return icmp;
    if(ip_H->protocol == IPPROTO_IGMP)
        return igmp;
    if(ip_H->protocol == IPPROTO_TCP)
        return tcp;
    if(ip_H->protocol == IPPROTO_UDP)
        return udp;

    /************************************************/

    return -1;
}

int TCP_PACKET_Classification(const u_char* packet, Node * BlackList, uint8_t * my_ip)
{

    /**************Packet Parsing********************/

    Ethernet * eth_H = (Ethernet *)(packet);
    int eth_SIZE = 14;

    Ip * ip_H = (Ip *)(packet + eth_SIZE);
    int ip_SIZE = (ip_H->VHL & 0x0F) * 4;
    int total_SIZE = ntohs(ip_H->Total_LEN);

    Tcp * tcp_H = (Tcp *)(packet + eth_SIZE + ip_SIZE);
    int tcp_SIZE = ((tcp_H->OFF & 0xF0) >> 4) * 4;

    u_char * payload = (u_char*)(packet + eth_SIZE + ip_SIZE + tcp_SIZE);
    int payload_len = (total_SIZE) - (ip_SIZE + tcp_SIZE);

    uint16_t d_port = ntohs(tcp_H->d_port);
    uint8_t flag=(tcp_H->flag & 0x3F);

    /************************************************/

    /*****************Port Scan*******************/

    //flag != 0x12 &&
    if(!memcmp(ip_H->d_ip,my_ip,4) && d_port !=0x0014 && d_port !=0x0015 && d_port !=0x0016
            && d_port != 0x0035 && d_port != 0x0050 && d_port != 0x01bb) // if not 20, 21, 22, 53, 80, 443 and if not _ip == my_ip And if not SYN+ACK
    {
        BlackList->AddBlackList(BlackList, ip_H->s_ip);
        printf("port : %02X%02X\n", (ntohs(tcp_H->d_port) >> 8) & 0xff , ntohs(tcp_H->d_port) & 0xff);
        printf("flag : %02X\n", flag);
        printf("AddBlackList\n");
        return -1;
    }

    /*********************************************/
    
    /***********XMAS or NULL Flag Attack**********/

    if(flag==0x00 || flag==0x3f)
    {
        BlackList->AddBlackList(BlackList, ip_H->s_ip);
        printf("flag : %02X\n", flag);
        printf("AddBlackList\n");
        return -1;
    }

    /*********************************************/


    /*************Tsunami Flood Attack************/

    if(flag!=0x08 && flag!=0x10 && flag!= 0x18 && (eth_SIZE + total_SIZE) > 94) // PSH, ACK, PSH + ACK, Packet SIZE
    {
        BlackList->AddBlackList(BlackList, ip_H->s_ip);
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

