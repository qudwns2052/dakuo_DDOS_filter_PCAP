#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>


typedef struct _Node
{
    uint8_t ip[4];
    struct _Node * next;

}Node;

Node * MakeNode(uint8_t * ip);
void AddBlackList(Node * head, uint8_t * ip);
bool FindBlackList(Node * head, uint8_t * ip);
