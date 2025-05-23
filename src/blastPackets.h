// taken from https://www.tutorialspoint.com/data_structures_algorithms/linked_list_program_in_c.htm

// header guard: avoids problems if this file is included twice
#ifndef PACKETSTOSEND_H
#define PACKETSTOSEND_H

//#include <stdio.h>
//#include <string.h>
//#include <stdlib.h>
//#include <arpa/inet.h>
//#include <sys/socket.h>

#include "commonFunctions.h"

#define MASK 0x03
#define HEARTBEAT 0x02
#define THISISANACK 0x01
#define ACKNEEDED 0x00


// header of the packet to be sent
typedef struct {
  uint16_t packetSize; // use 'htons()' when writing it because this field will be sent through the network
                       // use 'ntohs()' when reading it from the network
  uint8_t protocolID;
  uint16_t identifier; // use 'htons()' when writing it because this field will be sent through the network
                       // use 'ntohs()' when reading it from the network
  uint8_t ACK; // 0:this is a packet that requires an ACK; 1:the packet is an ACK; 2: the packet is a heartbeat
} __attribute__ ((__packed__)) simplemuxBlastHeader;


// include the payload and also other parameters that are not sent through the network
typedef struct storedPacketBlast {
  simplemuxBlastHeader header;
  uint8_t tunneledPacket[BUFSIZE];
  uint64_t sentTimestamp; // last moment when this packet was sent
  struct storedPacketBlast *next;
} __attribute__ ((__packed__)) storedPacketBlast;


//display the list
void printList(storedPacketBlast** head_ref);

//insert link at the first location
void insertFirst(storedPacketBlast** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload);

storedPacketBlast* findLast(storedPacketBlast** head_ref);

storedPacketBlast* insertLast(storedPacketBlast** head_ref, uint16_t size, uint8_t* payload);

//delete first item
storedPacketBlast* deleteFirst(storedPacketBlast** head_ref);

//is list empty
bool isEmpty(storedPacketBlast* head_ref);

int length(storedPacketBlast** head_ref);

//find a link with given identifier
storedPacketBlast* find(storedPacketBlast** head_ref, uint16_t identifier);

void sendPacketBlastFlavor(contextSimplemux* context,
                           storedPacketBlast* packetToSend);

int sendExpiredPackets( contextSimplemux* context,
                        uint64_t now);

uint64_t findLastSentTimestamp(storedPacketBlast* head_ref);

//delete a link with given identifier
bool delete(storedPacketBlast** head_ref, uint16_t identifier);

void reverse(storedPacketBlast** head_ref);

uint64_t findLastSentTimestamp(storedPacketBlast* head_ref);

#endif // PACKETSTOSEND_H