#include "linked_list.h"

Node * MakeNode(uint8_t * ip)
{
    Node * newnode = (Node*)malloc(sizeof(Node));
    if(ip==nullptr)
        newnode->next=nullptr;
    else
        memcpy(newnode->ip, ip, 4);
    newnode->next = nullptr;

    return newnode;
}

void AddBlackList(Node * head, uint8_t * ip)
{
    Node * temp = head;
    Node * newnode = MakeNode(ip);

    while(temp != nullptr)
        temp = temp->next;

    temp->next = newnode;
}

bool FindBlackList(Node * head, uint8_t * ip)
{
    Node * temp = head;

    while(temp != nullptr)
    {
        if(!memcmp(temp->ip, ip, 4))
            return true;
        temp = temp->next;
    }
    return false;
}
