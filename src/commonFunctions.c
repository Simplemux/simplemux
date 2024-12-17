#include "commonFunctions.h"

// global variable (defined as 'extern' in the .h file)
int debug;            // 0:no debug
                      // 1:minimum debug level
                      // 2:medimum debug level
                      // 3:maximum debug level

// global variables related to RoHC compression (defined as 'extern' in the .h file)
unsigned int seed;
rohc_status_t status;

struct rohc_comp *compressor;         // the ROHC compressor
struct rohc_decomp *decompressor;     // the ROHC decompressor

// define the buffers that will contain the packets to compress/decompress
// 'rohc_buf_init_empty' is a macro defined in 'rohc-1.7.0\src\common\rohc\rohc_buf.h'
// When you declare 'struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFSIZE);',
//the macro 'rohc_buf_init_empty' will be expanded to initialize the ip_packet structure.

// The next code initializes the ip_packet structure with the ip_buffer pointer and BUFSIZE
//as the maximum length, while setting the other fields to zero
// Here's how the code would look after substituting the macro:
/*struct rohc_buf ip_packet = {
    .time = { .sec = 0, .nsec = 0 },
    .data = ip_buffer,
    .max_len = BUFSIZE,
    .offset = 0,
    .len = 0
};*/
uint8_t ip_buffer[BUFSIZE];     // the buffer that will contain the IPv4 packet to compress
struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFSIZE);

uint8_t rohc_buffer[BUFSIZE];   // the buffer that will contain the resulting ROHC packet
struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFSIZE);

uint8_t ip_buffer_d[BUFSIZE];   // the buffer that will contain the resulting IP decompressed packet
struct rohc_buf ip_packet_d = rohc_buf_init_empty(ip_buffer_d, BUFSIZE);

uint8_t rohc_buffer_d[BUFSIZE]; // the buffer that will contain the ROHC packet to decompress
struct rohc_buf rohc_packet_d = rohc_buf_init_empty(rohc_buffer_d, BUFSIZE);

uint8_t rcvd_feedback_buffer_d[BUFSIZE];  // the buffer that will contain the ROHC feedback packet received
struct rohc_buf rcvd_feedback = rohc_buf_init_empty(rcvd_feedback_buffer_d, BUFSIZE);

uint8_t feedback_send_buffer_d[BUFSIZE];  // the buffer that will contain the ROHC feedback packet to be sent
struct rohc_buf feedback_send = rohc_buf_init_empty(feedback_send_buffer_d, BUFSIZE);


#ifdef DEBUG
/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
// Variadic Function: The '...' is used to define functions that accept a variable number of arguments
void do_debug(int level, char *msg, ...) {

  va_list argp;

  if( debug >= level ) {
    va_start(argp, msg);
    if (level==1)
      vfprintf(stderr, ANSI_COLOR_RESET, argp);
    else if (level==2)
      vfprintf(stderr, ANSI_COLOR_YELLOW, argp);
    else if (level==3)
      vfprintf(stderr, ANSI_COLOR_CYAN, argp);
    vfprintf(stderr, msg, argp);
    vfprintf(stderr, ANSI_COLOR_RESET, argp);
    va_end(argp);
  }
}


/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
// Variadic Function: The '...' is used to define functions that accept a variable number of arguments
void do_debug_c(int level, char* color, char *msg, ...) {

  va_list argp;

  if( debug >= level ) {
    va_start(argp, msg);
    vfprintf(stderr, color, argp);
    vfprintf(stderr, msg, argp);
    vfprintf(stderr, ANSI_COLOR_RESET, argp);
    va_end(argp);
  }
}
#endif


/**************************************************************************
 * Functions to work with IP Headers *
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
  
  //do_debug_c(1, ANSI_COLOR_RESET, "Checksum: %i\n", iph->check);

  counter ++;
}


// Buid a Full IP Packet from the header and the data
void BuildFullIPPacket( struct iphdr iph,
                        uint8_t *data_packet,
                        uint16_t len_data,
                        uint8_t *full_ip_packet)
{
  #ifdef ASSERT
    // ensure that there is space in the buffer
    assert(sizeof(struct iphdr) + len_data <= BUFSIZE);
  #endif

  memset(full_ip_packet, 0, BUFSIZE);
  memcpy((struct iphdr*)full_ip_packet, &iph, sizeof(struct iphdr));
  memcpy((struct iphdr*)(full_ip_packet + sizeof(struct iphdr)), data_packet, len_data);
}


// Get the IP header from an IP packet
void GetIpHeader( struct iphdr *iph,
                  uint8_t *ip_packet)
{
  memcpy(iph,(struct iphdr*)ip_packet,sizeof(struct iphdr));
}

// Set the IP header in an IP Packet
void SetIpHeader( struct iphdr iph,
                  uint8_t *ip_packet)
{
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


/**************************************************************************
 * GetTimeStamp: Get a timestamp in microseconds from the OS              *
 **************************************************************************/
uint64_t GetTimeStamp() {
  struct timeval tv;
  gettimeofday(&tv,NULL);
  return tv.tv_sec*(uint64_t)1000000+tv.tv_usec;
}


/**************************************************************************
 * ToByte: convert an array of booleans to a char                         *
 **************************************************************************/
// usage example:
/*
char c;
// bits[0] is the less significant bit
bool bits[8]={false, true, false, true, false, true, false, false}; is character '*': 00101010
c = ToByte(bits);
do_debug_c(1, ANSI_COLOR_RESET, "%c\n",c );
// as a result it will print an asterisk
*/
uint8_t ToByte(bool b[8]) {
  int i;
  uint8_t c = 0;
  
  for (i=0; i < 8; ++i)
    if (b[i])
      c |= 1 << i;
  return c;
}


/**************************************************************************
 * FromByte: return an array of booleans from a char                      *
 **************************************************************************/
// stores in 'b' the value 'true' or 'false' depending on each bit of the byte 'c'
// b[0] is the less significant bit
void FromByte(uint8_t c, bool b[8]) {
  int i;
  for (i=0; i < 8; ++i)
    b[i] = (c & (1<<i)) != 0;
}


#ifdef DEBUG
/**************************************************************************
 * PrintByte: prints the bits of a byte                                   *
 **************************************************************************/
void PrintByte( int debug_level,
                int num_bits,
                bool b[8]) {

  // num_bits is the number of bits to print
  // if 'num_bits' is smaller than 7, the function prints an '_' instead of the value

  int i;
  for (i= 7 ; i>= num_bits ; i--) {
    do_debug_c( debug_level,
                ANSI_COLOR_RESET,
                "_");
  }
  for (i= num_bits -1 ; i>=0; i--) {
    if (b[i]) {
      do_debug_c( debug_level,
                  ANSI_COLOR_RESET,
                  "1");
    } else {
      do_debug_c( debug_level,
                  ANSI_COLOR_RESET,
                  "0");
    }
  }
}
#endif


#ifdef DEBUG
/**************************************************************************
************ dump a packet ************************************************
**************************************************************************/
void dump_packet (int packet_size,
                  uint8_t packet[BUFSIZE]) {
  int j;

  do_debug(2,"   ");
  for(j = 0; j < packet_size; j++) {
    do_debug_c(2, ANSI_COLOR_RESET, "%02x ", packet[j]);
    if(j != 0 && ((j + 1) % 16) == 0) {
      do_debug(2, "\n");
      if ( j != (packet_size -1 )) do_debug(2,"   ");
    }
    // separate in groups of 8 bytes
    else if((j != 0 ) && ((j + 1) % 8 == 0 ) && (( j + 1 ) % 16 != 0)) {
      do_debug(2, "  ");
    }
  }
  if(j != 0 && ((j ) % 16) != 0) {
    // be sure to go to the line
    do_debug(2, "\n");
  }
}
#endif


/**************************************************************************
 * return an string with the date and the time in format %Y-%m-%d_%H.%M.%S*
 **************************************************************************/
int date_and_time(char buffer[25]) {
  time_t timer;
  struct tm* tm_info;

  time(&timer);
  tm_info = localtime(&timer);
  strftime(buffer, 25, "%Y-%m-%d_%H.%M.%S", tm_info);
  return EXIT_SUCCESS;
}