#pragma once

#include <pcap.h>
#include <stdint.h>

#include "linked_list.h"

int Packet_Classification(const u_char* packet, Node * BalckList);
int TCP_PACKET_Classification(const u_char* packet, Node * BlackList);
