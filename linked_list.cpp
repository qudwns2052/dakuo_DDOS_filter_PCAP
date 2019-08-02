#include "linked_list.h"

void Node::AddBlackList(Node * head, uint8_t * ip)
{
    Node * temp = head;
    Node * newnode;
    newnode = new Node(ip);

    while(temp->next != nullptr)
        temp = temp->next;

    temp->next = newnode;
}

bool Node::FindBlackList(Node * head, uint8_t * ip)
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

void Node2::Add_count(void)
{
    this->count++;
}

int Node2::Get_count(void)
{
    return count;
}
