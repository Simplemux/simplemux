// taken from https://www.tutorialspoint.com/data_structures_algorithms/linked_list_program_in_c.htm

#include "packetsToSend.h"

//display the list
void printList(struct packet** head_ref) {
   struct packet *ptr = *head_ref;
   printf("\n[ ");
  
   //start from the beginning
   while(ptr != NULL) {
      printf("(%d,",ptr->header.identifier);
      for (int i = 0; i < ptr->header.packetSize; ++i) {
        printf("%c", ptr->packetPayload[i]);
      }
      printf(")");

      ptr = ptr->next;
   }
  
   printf(" ]\n");
}


//insert link at the first location
void insertFirst(struct packet** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload) {
   //create a link
   struct packet *link = (struct packet*) malloc(sizeof(struct packet));
  
   link->header.identifier = identifier;
   link->header.packetSize = size;
   memcpy(link->packetPayload,payload,link->header.packetSize);
  
   //point it to old first node
   link->next = *head_ref;
  
   //point first to new first node
   *head_ref = link;
}

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

//insert link at the last location
struct packet* insertLast(struct packet** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload) {

   // create a link
   struct packet *link = (struct packet*) malloc(sizeof(struct packet));

   // fill the content of the link  
   link->header.identifier = identifier;
   link->header.packetSize = size;
   memcpy(link->packetPayload,payload,link->header.packetSize);
   link->next = NULL;

   if(isEmpty(*head_ref)) {
      *head_ref = link;
      //printf("[insertLast] New link inserted in the first position\n");
   }
   else {
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

//is list empty
bool isEmpty(struct packet* head_ref) {
   if(head_ref == NULL)
      return true;
   else
      return false;
}


int length(struct packet** head_ref) {
   int length = 0;
   struct packet *current = *head_ref;

   if(current==NULL)
      return 0;
   else {
      length++;
      printf("[length] packet %d, %d bytes, last sent: %"PRIu64" us\n", length, current->header.packetSize, current->sentTimestamp);
   }

   while(current->next!=NULL) {
      length++;
      current=current->next;
      printf("[length] packet %d, %d bytes, last sent: %"PRIu64" us\n", length, current->header.packetSize, current->sentTimestamp);
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
   while(current->header.identifier != identifier) {
  
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


uint64_t findLastSentTimestamp(struct packet* head_ref) {
   //start from the first link
   struct packet* current = head_ref;

   //if list is empty
   if(head_ref == NULL) {
      return 1;
   }

   // initialize with the first packet
   uint64_t lastSentTimestamp = current->sentTimestamp;
   assert(current->sentTimestamp!=0);

   //navigate through the list
   while(current->next!=NULL) {
      if(current->sentTimestamp < lastSentTimestamp) {
         // this packet has been sent even before
         lastSentTimestamp = current->sentTimestamp;
      }

      current=current->next;
   }
   //printf("[findLastSentTimestamp] Oldest timestamp: packet %d. Timestamp: %"PRIu64" us\n", current->header.identifier, current->sentTimestamp);

   return lastSentTimestamp;
}

//delete a link with a given identifier
bool delete(struct packet** head_ref, uint16_t identifier) {

   //start from the first link
   struct packet* current = *head_ref;
   struct packet* previous = NULL;
  
   //if list is empty
   if(head_ref == NULL) {
      return false;
   }

   //navigate through the list
   while(current->header.identifier != identifier) {

      //if it is last node
      if(current->next == NULL) {
         return NULL;
      }
      else {
         //store reference to current link
         previous = current;
         //move to next link
         current = current->next;
      }
   }

   //found a match, update the link

   // if the link to delete is the first one
   if(current == *head_ref) {
      //change first to point to next link
      *head_ref = (*head_ref)->next;
      free(current);
   }
   // if the link to delete is not the first one
   else {
      //bypass the current link
      previous->next = current->next;
      free(current);
   }    
  
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

   insertLast(&head,7,packetSize2,packet2); 

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