#include "commonFunctions.h"

// global variable
int debug;            // 0:no debug; 1:minimum debug; 2:maximum debug 


/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(int level, char *msg, ...) {

  va_list argp;

  if( debug >= level ) {
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}


/**************************************************************************
 * Functions to work with IP Header *
 **************************************************************************/

// Calculate IPv4 checksum
unsigned short in_cksum(unsigned short *addr, int len) {
  register int sum = 0;
  u_short answer = 0;
  register u_short *w = addr;
  register int nleft = len;
  /*
  * Our algorithm is simple, using a 32 bit accumulator (sum), we add
  * sequential 16 bit words to it, and at the end, fold back all the
  * carry bits from the top 16 bits into the lower 16 bits.
  */
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }
  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(u_char *) (&answer) = *(u_char *) w;
    sum += answer;
  }
  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16); /* add carry */
  answer = ~sum; /* truncate to 16 bits */
  return (answer);
}


// Buid an IPv4 Header
void BuildIPHeader( struct iphdr *iph,
                    uint16_t len_data,
                    uint8_t ipprotocol,
                    struct sockaddr_in local,
                    struct sockaddr_in remote )
{
  static uint16_t counter = 0;

  // clean the variable
  memset (iph, 0, sizeof(struct iphdr));

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(sizeof(struct iphdr) + len_data);
  iph->id = htons(1234 + counter);
  iph->frag_off = 0;  // fragment is allowed
  iph->ttl = Linux_TTL;
  iph->protocol = ipprotocol;
  iph->saddr = inet_addr(inet_ntoa(local.sin_addr));
  //iph->saddr = inet_addr("192.168.137.1");
  iph->daddr = inet_addr(inet_ntoa(remote.sin_addr));

  iph->check = in_cksum((unsigned short *)iph, sizeof(struct iphdr));
  
  //do_debug(1, "Checksum: %i\n", iph->check);

  counter ++;
}

// Buid a Full IP Packet
void BuildFullIPPacket(struct iphdr iph, uint8_t *data_packet, uint16_t len_data, uint8_t *full_ip_packet) {
  memset(full_ip_packet, 0, BUFSIZE);
  memcpy((struct iphdr*)full_ip_packet, &iph, sizeof(struct iphdr));
  memcpy((struct iphdr*)(full_ip_packet + sizeof(struct iphdr)), data_packet, len_data);
}


//Get IP header from IP packet
void GetIpHeader(struct iphdr *iph, uint8_t *ip_packet) {  
  memcpy(iph,(struct iphdr*)ip_packet,sizeof(struct iphdr));
}

//Set IP header in IP Packet
void SetIpHeader(struct iphdr iph, uint8_t *ip_packet) {
  memcpy((struct iphdr*)ip_packet,&iph,sizeof(struct iphdr));
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, uint8_t *buf, int n) {

  int nread;

  if((nread=read(fd, buf, n)) < 0) {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, uint8_t *buf, int n) {

  int nwritten;

  if((nwritten = write(fd, buf, n)) < 0){
    perror("cwrite() Error writing data");
    exit(1);
  }
  return nwritten;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, uint8_t *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}


/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;

  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}