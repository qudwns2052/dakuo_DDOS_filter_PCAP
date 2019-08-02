#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

using namespace std;

class Node
{
public:
    uint8_t ip[4];
    Node * next;
    Node()
    {
        memset(this->ip, 0x00, 4);
        this->next=nullptr;
    }
    Node(uint8_t * ip)
    {
        memcpy(this->ip, ip, 4);
        this->next=nullptr;
    }
    void AddBlackList(Node * head, uint8_t * ip);
    bool FindBlackList(Node * head, uint8_t * ip);

};

class Node2 : public Node
{
public:
    int count;
    Node2() : Node()
    {
        count=0;
    }
    void Add_count(void);
    int Get_count(void);
};
