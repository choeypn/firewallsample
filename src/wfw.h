//Header file for wfw.c
//

typedef struct frame{
	uint8_t  dst[6];
	uint8_t  src[6];
	uint16_t type;
	uint8_t  data[1500];	 
}frame_t;


typedef struct ipv6Hdr{
	unsigned int
		version: 4,
		priority : 8,
		flowLabel : 20;
	uint16_t length;
	uint8_t nextHdr;
	uint8_t hopLimit;
	unsigned char src[16];
	unsigned char dst[16];
	uint8_t headers[];
}ipv6Hdr_t;

typedef struct tcpsegment{
	uint16_t srcPort;
	uint16_t dstPort;
	uint32_t seqNum;
	uint32_t ackNum;
	unsigned int 
		hdrsz : 4,
		resev : 3,
		NS		: 1,
		CWR		: 1,
		ECE		: 1,
		URG		: 1,
		ACK		: 1,
		PSH		: 1,
		RST		: 1,
		SYN		: 1,
		FIN		: 1;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent;
	uint32_t options[];

}tcpsegment;

typedef struct cookie{
	void* localPort;
	void* remotePort;
	void* remoteAddr;	
}cookie;


/* Globals  */
static char* conffile   = STR(SYSCONFDIR) "/wfw.cfg";
static bool  printusage = false;
static bool  foreground = false;

/* Prototypes */

/* Parse Options
 * argc, argv   The command line
 * returns      true iff the command line is successfully parsed
 *
 * This function sets the otherwise immutable global variables (above).  
 */
static
bool parseoptions(int argc, char* argv[]);

/* Usage
 * cmd   The name by which this program was invoked
 * file  The steam to which the usage statement is printed
 *
 * This function prints the simple usage statement.  This is typically invoked
 * if the user provides -h on the command line or the options don't parse.  
 */
static
void usage(char* cmd, FILE* file);

/* Ensure Tap
 * path     The full path to the tap device.
 * returns  If this function returns, it is the file descriptor for the tap
 *          device. 
 * 
 * This function tires to open the specified device for reading and writing.  If
 * that open fails, this function will report the error to stderr and exit the
 * program.   
 */
static
int  ensuretap(char* path);

/* Ensure Socket
 * localaddress   The IPv4 address to bind this socket to.
 * port           The port number to bind this socket to.
 *
 * This function creates a bound socket.  Notice that both the local address and
 * the port number are strings.  
 */
static
int ensuresocket(char* localaddr, char* port);

/* Make Socket Address
 * address, port  The string representation of an IPv4 socket address.
 *
 * This is a convince routine to convert an address-port pair to an IPv4 socket
 * address.  
 */
static
struct sockaddr_in makesockaddr(char* address, char* port);

/* mkfdset
 * set    The fd_set to populate
 * ...    A list of file descriptors terminated with a zero.
 *
 * This function will clear the fd_set then populate it with the specified file
 * descriptors.  
 */
static
int mkfdset(fd_set* set, ...);

/* Bridge 
 * tap     The local tap device
 * in      The network socket that receives broadcast packets.
 * out     The network socket on with to send broadcast packets.
 * bcaddr  The broadcast address for the virtual ethernet link.
 *
 * This is the main loop for wfw.  Data from the tap is broadcast on the
 * socket.  Data broadcast on the socket is written to the tap.  
 */
static
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr);

//duplicate input
static void* memdup(void* p, size_t s);
//check incoming mac if is special mac
static bool isspecialmac(unsigned char* mac);

/* daemonize
 * make this process a daemon process
*/
static void daemonize(hashtable conf);

