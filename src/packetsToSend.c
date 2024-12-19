// taken from https://www.tutorialspoint.com/data_structures_algorithms/linked_list_program_in_c.htm

#include "packetsToSend.h"

//display the list
void printList(packet** head_ref) {
  packet *ptr = *head_ref;
  printf("List of stored packets: [ ");
  
  while(ptr != NULL) {
    printf("(%d,%"PRIu64"",ntohs(ptr->header.identifier),ptr->sentTimestamp);
    printf(")");

    ptr = ptr->next;
  }

  printf(" ]\n");
}


//insert link at the first location
void insertFirst(packet** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload) {
  //create a link
  packet *link = (packet*) malloc(sizeof(packet));
  
  link->header.identifier = htons(identifier);
  link->header.packetSize = htons(size);
  memcpy(link->tunneledPacket,payload,ntohs(link->header.packetSize));
  
  //point it to old first node
  link->next = *head_ref;
  
  //point first to new first node
  *head_ref = link;
}


// find the last packet
packet* findLast( packet** head_ref) {

  if(isEmpty(*head_ref)) {
    //printf("[findLast] Empty list\n");
    return NULL;
  }
  else {
    // the list at least has 1 element
    int length = 1;
    packet *current = *head_ref;
    while(current->next != NULL) {
      current = current->next;
      length ++;
    }
    //printf("[findLast] Number of elements of the list: %d\n", length);
    return current;     
  }
}


//insert packet at the last location
packet* insertLast(packet** head_ref, uint16_t size, uint8_t* payload) {

  // create a link
  packet *link = (packet*) malloc(sizeof(packet));

  // fill the content of the link  
  if(size!=0)
    link->header.packetSize = htons(size);

  if(payload!=NULL)
    memcpy(link->tunneledPacket,payload,ntohs(link->header.packetSize));

  link->next = NULL;

  // check if this is the first packet
  if(isEmpty(*head_ref)) {
    *head_ref = link;
    //printf("[insertLast] New link inserted in the first (and last) position (this is the only packet of the list)\n");
  }
  else {
    // this is not the first packet

    // find the last packet of the list
    packet *last = findLast(head_ref);

    // insert the new link
    last->next = link;     
    //printf("[insertLast] New link inserted\n");
  }
  return link;
}


//delete first item
packet* deleteFirst(packet** head_ref) {

  //save reference to first link
  packet *tempLink = *head_ref;

  //mark next to first link as first 
  *head_ref = (*head_ref)->next;

  //return the deleted link
  return tempLink;
}


//is the list empty?
bool isEmpty(packet* head_ref) {
  if(head_ref == NULL)
    return true;
  else
    return false;
}


int length(packet** head_ref) {
  int length = 0;
  packet *current = *head_ref;

  while(current!=NULL) {
    length++;
    current=current->next;
  }
  return length;
}


//find a link with given identifier
packet* find(packet** head_ref, uint16_t identifier) {

  //start from the first link
  packet* current = *head_ref;

  //if list is empty
  if(head_ref == NULL) {
    return NULL;
  }

  //navigate through list
  while(ntohs(current->header.identifier) != identifier) {

    //if it is last node
    if(current->next == NULL) {
      return NULL;
    }
    else {
      //go to next link
      current = current->next;
    }
  }     

  //if data found, return the current Link
  return current;
}


void sendPacketBlastFlavor( contextSimplemux* context,
                            packet* packetToSend)
{
  // send the tunneled packet
  // 'packetToSend' is a pointer to the packet

  // calculate the length of the Simplemux header + the tunneled packet
  int total_length = sizeof(simplemuxBlastHeader) + ntohs(packetToSend->header.packetSize);

  switch (context->mode) {
    case UDP_MODE:
      #ifdef DEBUG
        if (packetToSend->header.ACK == HEARTBEAT) {
          // heartbeats have no ID, so the debug information does not show it
          do_debug_c( 3,
                      ANSI_COLOR_BOLD_GREEN,
                      "  Sending to the network a UDP blast heartbeat: %i bytes\n",
                      total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);      
        }
        else {
          do_debug_c( 3,
                      ANSI_COLOR_BOLD_GREEN,
                      "  Sending to the network a UDP blast packet with ID %i: %i bytes\n",
                      ntohs(packetToSend->header.identifier),
                      total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);      
        }
        do_debug_c( 3,
                    ANSI_COLOR_BOLD_GREEN,
                    "  Added tunneling header: %i bytes\n",
                    IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
      #endif

      // send the packet
      if (sendto( context->udp_mode_fd,
                  &(packetToSend->header),
                  total_length,
                  0,
                  (struct sockaddr *)&(context->remote),
                  sizeof(context->remote))==-1)
      {
        perror("sendto() in UDP mode failed");
        exit (EXIT_FAILURE);
      }
      else {
        context->tun2net++;
        // only increase the identifier for regular blast packets
        if (packetToSend->header.ACK == ACKNEEDED) {
          context->blastIdentifier++;
        }
      }
      
      #ifdef LOGFILE
        // write in the log file
        if ( context->log_file != NULL ) {
          if (packetToSend->header.ACK == HEARTBEAT) {
            // heartbeat
            fprintf ( context->log_file,
                      "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\t\tblastHeartbeat\n",
                      GetTimeStamp(),
                      total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE,
                      context->tun2net,
                      inet_ntoa(context->remote.sin_addr),
                      ntohs(context->remote.sin_port),
                      0); // in blast mode, no packet from tun/tap is sent in a heartbeat
          }
          else if (packetToSend->header.ACK == THISISANACK) {
            // ACK
            fprintf ( context->log_file,
                      "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\t\tblastACK\t%"PRIu16"\n",
                      GetTimeStamp(),
                      total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE,
                      context->tun2net,
                      inet_ntoa(context->remote.sin_addr),
                      ntohs(context->remote.sin_port),
                      0, // in blast mode, no packet from tun/tap is sent in an ACK
                      htons(packetToSend->header.identifier));
          }
          else {
            // blast packet
            #ifdef ASSERT
              assert(packetToSend->header.ACK == ACKNEEDED);
            #endif
            fprintf ( context->log_file,
                      "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\t\tblastPacket\t%"PRIu16"\n",
                      GetTimeStamp(),
                      total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE,
                      context->tun2net,
                      inet_ntoa(context->remote.sin_addr),
                      ntohs(context->remote.sin_port),
                      1, // in blast mode, only 1 packet from tun/tap is sent
                      htons(packetToSend->header.identifier));
          }
          fflush(context->log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write          
        }
      #endif

    break;

    case NETWORK_MODE: ; // I add a semicolon because the next command can be a statement
      #ifdef DEBUG
        if (packetToSend->header.ACK == HEARTBEAT) {
          // heartbeats have no ID, so the debug information does not show it
          do_debug_c( 3,
                      ANSI_COLOR_BOLD_GREEN,
                      "  Sending to the network an IP blast heartbeat: %i bytes\n",
                      total_length + IPv4_HEADER_SIZE);      
        }
        else {
          do_debug_c( 3,
                      ANSI_COLOR_BOLD_GREEN,
                      "  Sending to the network an IP blast packet with ID %i: %i bytes\n",
                      ntohs(packetToSend->header.identifier),
                      total_length + IPv4_HEADER_SIZE );
        }
        do_debug_c( 3,
                    ANSI_COLOR_BOLD_GREEN,
                    "  Added tunneling header: %i bytes\n",
                    IPv4_HEADER_SIZE );
      #endif

      // build the header
      struct iphdr ipheader;  
      uint8_t ipprotocol = IPPROTO_SIMPLEMUX_BLAST;
      BuildIPHeader(&ipheader,
                    total_length,
                    ipprotocol,
                    context->local,
                    context->remote);

      // build the full IP multiplexed packet
      uint8_t full_ip_packet[BUFSIZE]; // the full IP packet will be stored here
      BuildFullIPPacket(ipheader,
                        (uint8_t *)&(packetToSend->header),
                        total_length,
                        full_ip_packet);

      // send the packet
      if (sendto (context->network_mode_fd,
                  full_ip_packet,
                  total_length + sizeof(struct iphdr),
                  0,
                  (struct sockaddr *)&(context->remote),
                  sizeof (struct sockaddr)) < 0)
      {
        perror ("sendto() in Network mode failed");
        exit (EXIT_FAILURE);
      }
      else {
        context->tun2net++;
        // only increase the identifier for regular blast packets
        if (packetToSend->header.ACK == ACKNEEDED) {
          context->blastIdentifier++;
        }
      }

      #ifdef LOGFILE
        // write in the log file
        if ( context->log_file != NULL ) {
          if (packetToSend->header.ACK == HEARTBEAT) {
            // heartbeat
            fprintf ( context->log_file,
                      "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\t\tblastHeartbeat\n",
                      GetTimeStamp(),
                      total_length + IPv4_HEADER_SIZE,
                      context->tun2net,
                      inet_ntoa(context->remote.sin_addr),
                      // there is no port in network mode
                      0); // in blast mode, no packet from tun/tap is sent in a heartbeat
          }
          else if (packetToSend->header.ACK == THISISANACK) {
            // ACK
            fprintf ( context->log_file,
                      "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\t\tblastACK\t%"PRIu16"\n",
                      GetTimeStamp(),
                      total_length + IPv4_HEADER_SIZE,
                      context->tun2net,
                      inet_ntoa(context->remote.sin_addr),
                      // there is no port in network mode
                      0, // in blast mode, no packet from tun/tap is sent in an ACK
                      htons(packetToSend->header.identifier));
          }
          else {
            // blast packet
            #ifdef ASSERT
              assert(packetToSend->header.ACK == ACKNEEDED);
            #endif
            fprintf ( context->log_file,
                      "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\t\tblastPacket\t%"PRIu16"\n",
                      //"%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\t\tblastPacket\t%"PRIu16"\n",
                      GetTimeStamp(),
                      total_length + IPv4_HEADER_SIZE,
                      context->tun2net,
                      inet_ntoa(context->remote.sin_addr),
                      0,// there is no port in network mode
                      1, // in blast mode, only 1 packet from tun/tap is sent            
                      htons(packetToSend->header.identifier));
          }
          fflush(context->log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write
        }
      #endif
    break;
  }
}


// send again the packets which sentTimestamp + period >= now
int sendExpiredPackets( contextSimplemux* context,
                        uint64_t now)
{
  int sentPackets = 0; // number of packets sent
  packet *current = context->unconfirmedPacketsBlast;
  
  while(current != NULL) {
    #ifdef DEBUG
      do_debug_c( 3,
                  ANSI_COLOR_BOLD_GREEN,
                  "  Packet %d. Stored timestamp: %"PRIu64" us\n",
                  ntohs(current->header.identifier),
                  current->sentTimestamp);
    #endif
       
    if(current->sentTimestamp + context->period < now) {

      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_BOLD_GREEN,
                    "   Sending packet %d. Updated timestamp: %"PRIu64" us\n",
                    ntohs(current->header.identifier),
                    now); 

        do_debug_c( 3,
                    ANSI_COLOR_BOLD_GREEN,
                    "         Reason: Stored timestamp (%"PRIu64") + period (%"PRIu64") < now (%"PRIu64")\n",
                    current->sentTimestamp,
                    context->period,
                    now);
      #endif

      // this packet has to be sent
      current->sentTimestamp = now;

      // send the packet
      sendPacketBlastFlavor(context, current);

      sentPackets++;
    }
    else {
      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_BOLD_GREEN,
                    "   Not sending packet %d. Last sent at timestamp: %"PRIu64" us\n",
                    ntohs(current->header.identifier),
                    current->sentTimestamp);

        do_debug_c( 3,
                    ANSI_COLOR_BOLD_GREEN,
                    "         Reason: Stored timestamp (%"PRIu64") + period (%"PRIu64") >= now (%"PRIu64")\n",
                    current->sentTimestamp,
                    context->period,
                    now);
      #endif
    }

    current = current->next;
  }

  return sentPackets;
}


uint64_t findLastSentTimestamp (packet* head_ref)
{
  //start from the first link
  packet* current = head_ref;

  #ifdef DEBUG
    //printList(&head_ref);
  #endif

  if(head_ref == NULL) {
    return 0;
  }

  // I take the first packet of the list as the initial value of 'lastSentTimestamp'

  // first packet: it has been sent for sure
  #ifdef DEBUG
    do_debug_c( 3,
                ANSI_COLOR_BOLD_GREEN,
                "  Timestamp of packet %d: %"PRIu64" us\n",
                current->header.identifier,
                current->sentTimestamp);
  #endif

  // this packet has been sent before
  uint64_t lastSentTimestamp = current->sentTimestamp;

  #ifdef DEBUG
    uint16_t lastSentIdentifier = ntohs(current->header.identifier);
    do_debug_c( 3,
                ANSI_COLOR_BOLD_GREEN,
                "  Oldest timestamp so far: packet %d. Timestamp: %"PRIu64" us\n",
                lastSentIdentifier,
                lastSentTimestamp);
  #endif

  // move to the second packet
  current=current->next;

  // navigate through the rest of the list
  while(current != NULL) {
    #ifdef DEBUG
      do_debug_c( 3,
                  ANSI_COLOR_BOLD_GREEN,
                  "  Timestamp of packet %d: %"PRIu64" us\n",
                  current->header.identifier,
                  current->sentTimestamp);
    #endif

    if(current->sentTimestamp < lastSentTimestamp) {
      // this packet has been sent even before
      lastSentTimestamp = current->sentTimestamp;
       
      #ifdef DEBUG
        lastSentIdentifier = ntohs(current->header.identifier);
      #endif
    }

    #ifdef DEBUG
      do_debug_c( 3,
                  ANSI_COLOR_BOLD_GREEN,
                  "  Oldest timestamp so far: packet %d. Timestamp: %"PRIu64" us\n",
                  lastSentIdentifier,
                  lastSentTimestamp);
    #endif

    current=current->next;
  }

  #ifdef DEBUG
    do_debug_c( 3,
                ANSI_COLOR_BOLD_GREEN,
                "  Oldest timestamp: packet %d. Timestamp: %"PRIu64" us\n",
                lastSentIdentifier,
                lastSentTimestamp);
  #endif

  return lastSentTimestamp;
}


//delete a link with a given identifier
// inspired by https://www.geeksforgeeks.org/linked-list-set-3-deleting-node/
bool delete(packet** head_ref, uint16_t identifier) {

  packet* temp = *head_ref, *prev;

  // If the head node itself holds the key to be deleted
  if (temp != NULL && ntohs(temp->header.identifier) == identifier) {
    *head_ref = temp->next; // Changed head
    free(temp); // free old head
    return true;
  }

  // Search for the key to be deleted, keep track of the
  // previous node as we need to change 'prev->next'
  while (temp != NULL && ntohs(temp->header.identifier) != identifier) {
    prev = temp;
    temp = temp->next;
  }

  // If the key was not present in linked list
  if (temp == NULL)
    return false;

  // Unlink the node from linked list
  prev->next = temp->next;

  free(temp); // Free memory

  return true;
}


void reverse(packet** head_ref) {
  packet* prev    = NULL;
  packet* current = *head_ref;
  packet* next;

  while (current != NULL) {
    next  = current->next;
    current->next = prev;    
    prev = current;
    current = next;
  }

  *head_ref = prev;
}


void test() {
  packet *head = NULL;

  uint8_t packet1[BUFSIZE]= "Hello World";
  uint8_t packet2[BUFSIZE]= "Hello World2";
  uint16_t packetSize1 = 11;
  uint16_t packetSize2 = 12;

  packet *last = findLast(&head);
  printf("Last element of the list: ");
  printList(&last);

  insertFirst(&head,1,packetSize1,packet1);
  insertFirst(&head,2,packetSize2,packet2);
  insertFirst(&head,3,packetSize1,packet1);
  insertFirst(&head,4,packetSize2,packet2);
  insertFirst(&head,5,packetSize1,packet1);
  insertFirst(&head,6,packetSize2,packet2);
  printf("Original List: "); 
  //print list
  printList(&head);

  packet *current = insertLast(&head,7,/*packetSize2,*/packet2); 
  current->header.packetSize=packetSize2;

  printf("List with 7 elements: "); 

  //print list
  printList(&head);

  last = findLast(&head);
  printf("Last element of the list: ");
  printList(&last);

  while(!isEmpty(head)) {        
    packet *temp = deleteFirst(&head);
    printf("\nDeleted value:");
    printf("(%d) ",temp->header.identifier);
  }  

  printf("\nList after deleting all items: ");
  printList(&head);

  last = findLast(&head);
  printf("Last element of the list: ");
  printList(&last);

  insertFirst(&head,5,packetSize1,packet1);
  insertFirst(&head,1,packetSize1,packet1);
  insertFirst(&head,2,packetSize2,packet2);
  insertFirst(&head,3,packetSize1,packet1);
  insertFirst(&head,4,packetSize2,packet2);
  insertFirst(&head,6,packetSize2,packet2); 
  
  printf("\nRestored List: ");
  printList(&head);
  printf("\n");  

  last = findLast(&head);
  printf("Last element of the list: ");
  printList(&last);

  packet *foundLink = find(&head,4);

  if(foundLink != NULL) {
    printf("Element found: ");
    printf("(%d) ",foundLink->header.identifier);
    printf("\n");  
  }
  else {
    printf("Element not found");
  }

  if (delete(&head,4)) {
    printf("Element %d found\n", 4);
  }
  printf("List after deleting the found item: ");
  printList(&head);
  printf("\n");
  foundLink = find(&head,4);

  if(foundLink != NULL) {
    printf("Element found: ");
    printf("(%d) ",foundLink->header.identifier);
    printf("\n");
  }
  else {
    printf("Element not found.");
  }

  printf("\n");

  reverse(&head);
  printf("\nList after reversing the data: ");
  printList(&head);

  last = findLast(&head);
  printf("Last element of the list: ");
  printList(&last);
}