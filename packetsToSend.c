// taken from https://www.tutorialspoint.com/data_structures_algorithms/linked_list_program_in_c.htm

#include "packetsToSend.h"

//display the list
void printList(struct packet** head_ref) {
   struct packet *ptr = *head_ref;
   printf("\n[ ");
  
   //start from the beginning
   while(ptr != NULL) {
      printf("(%d,",ptr->identifier);
      for (int i = 0; i < ptr->packetSize; ++i) {
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
  
   link->identifier = identifier;
   link->packetSize = size;
   memcpy(link->packetPayload,payload,link->packetSize);
  
   //point it to old first node
   link->next = *head_ref;
  
   //point first to new first node
   *head_ref = link;
}

struct packet* findLast(struct packet** head_ref) {

   if(isEmpty(head_ref)) {
      printf("[findLast] Empty list\n");
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
      printf("[findLast] Number of elements of the list: %d\n", length);
      return current;      
   }
}

//insert link at the last location
struct packet* insertLast(struct packet** head_ref, uint16_t identifier, uint16_t size, uint8_t* payload) {

   // create a link
   struct packet *link = (struct packet*) malloc(sizeof(struct packet));

   // fill the content of the link  
   link->identifier = identifier;
   link->packetSize = size;
   memcpy(link->packetPayload,payload,link->packetSize);
   link->next = NULL;

   // find the last packet of the list
   struct packet *last = findLast(head_ref);

   // insert the new link
   last->next = link;

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
bool isEmpty(struct packet** head_ref) {
   return *head_ref == NULL;
}


int length(struct packet** head_ref) {
   int length = 0;
   struct packet *current;
  
   for(current = *head_ref; current != NULL; current = current->next) {
      length++;
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
   while(current->identifier != identifier) {
  
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
   while(current->identifier != identifier) {

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

void main() {
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

   while(!isEmpty(&head)) {            
      struct packet *temp = deleteFirst(&head);
      printf("\nDeleted value:");
      printf("(%d) ",temp->identifier);
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
      printf("(%d) ",foundLink->identifier);
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
      printf("(%d) ",foundLink->identifier);
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