// taken from https://www.tutorialspoint.com/data_structures_algorithms/linked_list_program_in_c.htm

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>  // required for using uint8_t, uint16_t, etc.
#include "commonFunctions.h"

#define MASK 0x03
#define HEARTBEAT 0x02
#define THISISANACK 0x01
#define ACKNEEDED 0x00

// header of the packet to be sent
struct simplemuxBlastHeader {
   uint16_t packetSize; // use 'htons()' when writing it because this field will be sent through the network
                        // use 'ntohs()' when reading it from the network
   uint8_t protocolID;
   uint16_t identifier; // use 'htons()' when writing it because this field will be sent through the network
                        // use 'ntohs()' when reading it from the network
   uint8_t ACK; // 0:this is a packet that requires an ACK; 1:the packet is an ACK; 2: the packet is a heartbeat
} __attribute__ ((__packed__));

// include the payload and also other parameters that are not sent through the network
struct packet {
   struct simplemuxBlastHeader header;
   uint8_t tunneledPacket[BUFSIZE];
   uint64_t sentTimestamp; // last moment when this packet was sent
   struct packet *next;
} __attribute__ ((__packed__));

//display the list
void printList(struct packet** head_ref);

//insert link at the first location
void insertFirst(struct packet** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload);

struct packet* findLast(struct packet** head_ref);

struct packet* insertLast(struct packet** head_ref, /*uint16_t identifier,*/ uint16_t size, uint8_t* payload);

//delete first item
struct packet* deleteFirst(struct packet** head_ref);

//is list empty
bool isEmpty(struct packet* head_ref);

int length(struct packet** head_ref);

//find a link with given identifier
struct packet* find(struct packet** head_ref, uint16_t identifier);

void sendPacketBlastMode(  int fd,
                           int mode,
                           struct packet* packetToSend,
                           struct sockaddr_in remote,
                           struct sockaddr_in local);

int sendExpiredPackects(struct packet* head_ref,
                        uint64_t now,
                        uint64_t period,
                        int fd,
                        int mode,
                        struct sockaddr_in remote,
                        struct sockaddr_in local);

uint64_t findLastSentTimestamp(struct packet* head_ref);

//delete a link with given identifier
bool delete(struct packet** head_ref, uint16_t identifier);

void reverse(struct packet** head_ref);

uint64_t findLastSentTimestamp(struct packet* head_ref);