// taken from https://www.tutorialspoint.com/data_structures_algorithms/linked_list_program_in_c.htm

#include "packetsToSend.h"

//display the list
void printList(struct packet** head_ref) {
   struct packet *ptr = *head_ref;
   printf("List of stored packets: [ ");
  
   while(ptr != NULL) {
      printf("(%d,%"PRIu64"",ntohs(ptr->header.identifier),ptr->sentTimestamp);
      //for (int i = 0; i < ptr->header.packetSize; ++i) {
      //  printf("%c", ptr->tunneledPacket[i]);
      //}
      printf(")");

      ptr = ptr->next;
   }
  
   printf(" ]\n");
}


//insert link at the first location
void insertFirst(struct packet** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload) {
   //create a link
   struct packet *link = (struct packet*) malloc(sizeof(struct packet));
  
   link->header.identifier = htons(identifier);
   link->header.packetSize = htons(size);
   memcpy(link->tunneledPacket,payload,ntohs(link->header.packetSize));
  
   //point it to old first node
   link->next = *head_ref;
  
   //point first to new first node
   *head_ref = link;
}


// find the last packet
struct packet* findLast(struct packet** head_ref) {

   if(isEmpty(*head_ref)) {
      //printf("[findLast] Empty list\n");
      return NULL;
   }
   else {
      // the list at least has 1 element
      int length = 1;
      struct packet *current = *head_ref;
      while(current->next != NULL) {
         current = current->next;
         length ++;
      }
      //printf("[findLast] Number of elements of the list: %d\n", length);
      return current;      
   }
}


//insert packet at the last location
struct packet* insertLast(struct packet** head_ref, /*uint16_t identifier,*/ uint16_t size, uint8_t* payload) {

   // create a link
   struct packet *link = (struct packet*) malloc(sizeof(struct packet));

   // fill the content of the link  
   //link->header.identifier = identifier;
   if(size!=0)
      link->header.packetSize = htons(size);
   
   if(payload!=NULL)
      memcpy(link->tunneledPacket,payload,ntohs(link->header.packetSize));
   
   link->next = NULL;

   // check if this is the first packet
   if(isEmpty(*head_ref)) {
      *head_ref = link;
      //printf("[insertLast] New link inserted in the first position\n");
   }
   else {
      // this is not the first packet

      // find the last packet of the list
      struct packet *last = findLast(head_ref);

      // insert the new link
      last->next = link;      
      //printf("[insertLast] New link inserted\n");
   }

   return link;
}


//delete first item
struct packet* deleteFirst(struct packet** head_ref) {

   //save reference to first link
   struct packet *tempLink = *head_ref;
  
   //mark next to first link as first 
   *head_ref = (*head_ref)->next;
  
   //return the deleted link
   return tempLink;
}


//is the list empty?
bool isEmpty(struct packet* head_ref) {
   if(head_ref == NULL)
      return true;
   else
      return false;
}


int length(struct packet** head_ref) {
   int length = 0;
   struct packet *current = *head_ref;
   
   while(current!=NULL) {
      length++;
      current=current->next;
   }

   return length;
}


//find a link with given identifier
struct packet* find(struct packet** head_ref, uint16_t identifier) {

   //start from the first link
   struct packet* current = *head_ref;

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


void sendPacketBlastMode(  int fd,
                           int mode,
                           struct packet* packetToSend,
                           struct sockaddr_in remote,
                           struct sockaddr_in local)
{
   // send the tunneled packet
   // fd is the file descriptor of the socket
   // 'mode' is UDP_MODE or NETWORK_MODE
   // 'packetToSend' is a pointer to the packet

   // calculate the length of the Simplemux header + the tunneled packet
   int total_length = sizeof(struct simplemuxBlastHeader) + ntohs(packetToSend->header.packetSize);

   switch (mode) {
      case UDP_MODE:
         do_debug(3, "[sendPacketBlastMode] Sending to the network a UDP blast packet with ID %i: %i bytes\n", ntohs(packetToSend->header.identifier), total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
         do_debug(3, "[sendPacketBlastMode]  Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);

        // send the packet
        if (sendto(fd, &(packetToSend->header), total_length, 0, (struct sockaddr *)&remote, sizeof(remote))==-1) {
          perror("sendto() in UDP mode failed");
          exit (EXIT_FAILURE);
        }
        /*
        // write in the log file
        if ( log_file != NULL ) {
          fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
          fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
        }*/
      break;

      case NETWORK_MODE:
         do_debug(3, "[sendPacketBlastMode] Sending to the network an IP blast packet with ID %i: %i bytes\n", ntohs(packetToSend->header.identifier), total_length + IPv4_HEADER_SIZE );
         do_debug(3, "[sendPacketBlastMode]  Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );

        // build the header
        struct iphdr ipheader;  
        uint8_t ipprotocol = IPPROTO_SIMPLEMUX_BLAST;
        BuildIPHeader(&ipheader, total_length, ipprotocol, local, remote);

        // build the full IP multiplexed packet
        uint8_t full_ip_packet[BUFSIZE]; // the full IP packet will be stored here
        BuildFullIPPacket(ipheader, (uint8_t *)&(packetToSend->header), total_length, full_ip_packet);

        // send the packet
        if (sendto (fd, full_ip_packet, total_length + sizeof(struct iphdr), 0, (struct sockaddr *)&remote, sizeof (struct sockaddr)) < 0)  {
          perror ("sendto() in Network mode failed");
          exit (EXIT_FAILURE);
        }
        /*
        // write in the log file
        if ( log_file != NULL ) {
          fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), num_pkts_stored_from_tun);
          fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
        }*/
      break;
   }
}


// send again the packets which sentTimestamp + period >= now
int sendExpiredPackects(struct packet* head_ref,
                        uint64_t now,
                        uint64_t period,
                        int fd,
                        int mode,
                        struct sockaddr_in remote,
                        struct sockaddr_in local)
{

   //do_debug(3,"[sendExpiredPackects] starting\n");
   
   int sentPackets = 0; // number of packets sent
   struct packet *current = head_ref;
   
   while(current != NULL) {
      do_debug(3,"[sendExpiredPackects] Packet %d. Stored timestamp: %"PRIu64" us\n", ntohs(current->header.identifier),current->sentTimestamp);
         
      if(current->sentTimestamp + period < now) {

         do_debug(3,"[sendExpiredPackects]  Sending packet %d. Updated timestamp: %"PRIu64" us\n", ntohs(current->header.identifier), now); 
         do_debug(3,"                        Reason: Stored timestamp (%"PRIu64") + period (%"PRIu64") < now (%"PRIu64")\n", current->sentTimestamp, period, now);

         // this packet has to be sent
         current->sentTimestamp = now;

         // send the packet
         sendPacketBlastMode( fd, mode, current, remote, local);

         sentPackets++;
      }
      else {
         do_debug(3,"[sendExpiredPackects]  Not sending packet %d. Last sent at timestamp: %"PRIu64" us\n", ntohs(current->header.identifier), current->sentTimestamp);
         do_debug(3,"                        Reason: Stored timestamp (%"PRIu64") + period (%"PRIu64") >= now (%"PRIu64")\n", current->sentTimestamp, period, now);
      }

      current = current->next;
   }

   return sentPackets;
}


uint64_t findLastSentTimestamp(struct packet* head_ref) {
  
   //start from the first link
   struct packet* current = head_ref;

   //printList(&head_ref);

   if(head_ref == NULL) {
      return 0;
   }

   // I take the first packet of the list as the initial value of 'lastSentTimestamp'

   // first packet: it has been sent for sure
   do_debug(3,"[findLastSentTimestamp] Timestamp of packet %d: %"PRIu64" us\n", current->header.identifier, current->sentTimestamp);

   // this packet has been sent before
   uint64_t lastSentTimestamp = current->sentTimestamp;
   uint16_t lastSentIdentifier = ntohs(current->header.identifier);

   do_debug(3,"[findLastSentTimestamp] Oldest timestamp so far: packet %d. Timestamp: %"PRIu64" us\n", lastSentIdentifier, lastSentTimestamp);

   // move to the second packet
   current=current->next;

   // navigate through the rest of the list
   while(current!=NULL) {
      do_debug(3,"[findLastSentTimestamp] Timestamp of packet %d: %"PRIu64" us\n", current->header.identifier, current->sentTimestamp);
      if(current->sentTimestamp < lastSentTimestamp) {
         // this packet has been sent even before
         lastSentTimestamp = current->sentTimestamp;
         lastSentIdentifier = ntohs(current->header.identifier);
      }
      do_debug(3,"[findLastSentTimestamp] Oldest timestamp so far: packet %d. Timestamp: %"PRIu64" us\n", lastSentIdentifier, lastSentTimestamp);

      current=current->next;
   }


   do_debug(3,"[findLastSentTimestamp] Oldest timestamp: packet %d. Timestamp: %"PRIu64" us\n", lastSentIdentifier, lastSentTimestamp);

   return lastSentTimestamp;
}


//delete a link with a given identifier
// inspired by https://www.geeksforgeeks.org/linked-list-set-3-deleting-node/
bool delete(struct packet** head_ref, uint16_t identifier) {

   struct packet* temp = *head_ref, *prev;

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


void reverse(struct packet** head_ref) {
   struct packet* prev   = NULL;
   struct packet* current = *head_ref;
   struct packet* next;
  
   while (current != NULL) {
      next  = current->next;
      current->next = prev;   
      prev = current;
      current = next;
   }
  
   *head_ref = prev;
}

void test() {
   struct packet *head = NULL;

   uint8_t packet1[BUFSIZE]= "Hello World";
   uint8_t packet2[BUFSIZE]= "Hello World2";
   uint16_t packetSize1 = 11;
   uint16_t packetSize2 = 12;

   struct packet *last = findLast(&head);
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

   struct packet *current = insertLast(&head,7,/*packetSize2,*/packet2); 
   current->header.packetSize=packetSize2;

   printf("List with 7 elements: "); 
  
   //print list
   printList(&head);

   last = findLast(&head);
   printf("Last element of the list: ");
   printList(&last);

   while(!isEmpty(head)) {            
      struct packet *temp = deleteFirst(&head);
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

   struct packet *foundLink = find(&head,4);
  
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