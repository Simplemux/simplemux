// taken from https://www.tutorialspoint.com/data_structures_algorithms/linked_list_program_in_c.htm

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>  // required for using uint8_t, uint16_t, etc.

#define BUFSIZE 2304

// header of the packet to be sent
struct packetHeader {
   uint16_t packetSize;
   uint8_t protocolID;
   uint16_t identifier;
   uint8_t ACK; // 0: do nothing; 1: this is a packet that requires an ACK; 2: this is an ACK
};

// include the payload and also other parameters that are not sent through the network
struct packet {
   struct packetHeader header;
   uint8_t packetPayload[BUFSIZE];
   uint64_t sentTimestamp; // last moment when this packet was sent
   struct packet *next;
};


//display the list
void printList(struct packet** head_ref);

//insert link at the first location
void insertFirst(struct packet** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload);

struct packet* findLast(struct packet** head_ref);

struct packet* insertLast(struct packet** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload);

//delete first item
struct packet* deleteFirst(struct packet** head_ref);

//is list empty
bool isEmpty(struct packet* head_ref);

int length(struct packet** head_ref);

//find a link with given identifier
struct packet* find(struct packet** head_ref, uint16_t identifier);

int sendExpiredPackects(struct packet* head_ref, uint64_t now, uint64_t period);

uint64_t findLastSentTimestamp(struct packet* head_ref);

//delete a link with given identifier
bool delete(struct packet** head_ref, uint16_t identifier);

void reverse(struct packet** head_ref);

uint64_t findLastSentTimestamp(struct packet* head_ref);