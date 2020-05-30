#include "conf.h"
#include "hash.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Constants */
#define STR1(x)   #x
#define STR(x)    STR1(x)
#define DEVICE    "device"
#define PORT      "port"
#define BROADCAST "broadcast"
#define ANYIF     "0.0.0.0"
#define ANYPORT   "0"
#define PID 			"pidfile"

#include "wfw.h"

/* Main
 * 
 * Mostly, main parses the command line, the conf file, creates the necessary
 * structures and then calls bridge.  Bridge is where the real work is done. 
 */
int main(int argc, char* argv[]) {
  int result = EXIT_SUCCESS;

  if(!parseoptions(argc, argv)) {
    usage(argv[0], stderr);
    result = EXIT_FAILURE;
  }
  else if(printusage) {
    usage(argv[0], stdout);
  }
  else {
    hashtable conf = readconf (conffile);
    int       tap  = ensuretap (htstrfind (conf, DEVICE));
    int       out  = ensuresocket(ANYIF, ANYPORT);
    int       in   = ensuresocket(htstrfind (conf, BROADCAST),
                                  htstrfind (conf, PORT));
    struct sockaddr_in
      bcaddr       = makesockaddr (htstrfind (conf,BROADCAST),
                                   htstrfind (conf, PORT));
		if(!foreground)
			daemonize(conf);
  
    bridge(tap, in, out, bcaddr);
    
    close(in);
    close(out);
    close(tap);
    htfree(conf);
  }

  return result;
}



/* Parse Options
 *
 * see man 3 getopt
 */
static
bool parseoptions(int argc, char* argv[]) {
  static const char* OPTS = "hc:f";

  bool parsed = true;

  char c = getopt(argc, argv, OPTS);
  while(c != -1) {
    switch (c) {
    case 'c':
      conffile = optarg;
      break;
        
    case 'h':
      printusage = true;
      break;

		case 'f':
			foreground = true;
			break;

    case '?':
      parsed = false;
      break;
    }

    c = parsed ? getopt(argc, argv, OPTS) : -1;
  }

  if(parsed) {
    argc -= optind;
    argv += optind;
  }

  return parsed;
}

/* Print Usage Statement
 *
 */

static
void usage(char* cmd, FILE* file) {
  fprintf(file, "Usage: %s -c file.cfg [-h]\n", cmd);
}

/* Ensure Tap device is open.
 *
 */
static
int ensuretap(char* path) {
  int fd = open(path, O_RDWR | O_NOSIGPIPE);
  if(-1 == fd) {
    perror("open");
    fprintf(stderr, "Failed to open device %s\n", path);
    exit(EXIT_FAILURE);
  }
  return fd;
}

/* Ensure socket
 *
 * Note the use of atoi, htons, and inet_pton. 
 */
static
int ensuresocket(char* localaddr, char* port) {
  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  if(-1 == sock) {
    perror("socket");
    exit (EXIT_FAILURE);
  }

  int bcast = 1;
  if (-1 == setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                       &bcast, sizeof(bcast))) {
    perror("setsockopt(broadcast)");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in addr = makesockaddr(localaddr, port);
  if(0 != bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
    perror("bind");
    char buf[80];
    fprintf(stderr,
            "failed to bind to %s\n",
            inet_ntop(AF_INET, &(addr.sin_addr), buf, 80));
    exit(EXIT_FAILURE);
  }

  return sock;  
}

/* Make Sock Addr
 * 
 * Note the use of inet_pton and htons.
 */
static
struct sockaddr_in makesockaddr(char* address, char* port) {
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_len    = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(atoi(port));
  inet_pton(AF_INET, address, &(addr.sin_addr));
  return addr;
}

/* mkfdset
 *
 * Note the use of va_list, va_arg, and va_end. 
 */
static
int mkfdset(fd_set* set, ...) {
  int max = 0;
  
  FD_ZERO(set);
  
  va_list ap;
  va_start(ap, set);
  int s = va_arg(ap, int);
  while(s != 0) {
    if(s > max)
      max = s;
    FD_SET(s, set);
    s = va_arg(ap, int);
  }
  va_end(ap);
  
  return max;
}

/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom.  
 */
static
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr) {
  fd_set rdset;
  
  int maxfd = mkfdset(&rdset, tap, in, out, 0);
	
	hashtable hasht = htnew(100,(keycomp)memcmp,NULL);
	int sock;
	
	hashtable tcphash = htnew(100,(keycomp)memcmp,NULL);

  while(0 <= select(1+maxfd, &rdset, NULL, NULL, NULL)) {
    if(FD_ISSET(tap, &rdset)) {
			frame_t frame;
      ssize_t rdct = read(tap, &frame, sizeof(frame_t));
      if(rdct < 0) {
        perror("read");
      }
			else{
				if(frame.type == htons(0x86DD)){
					ipv6Hdr_t *packet = (ipv6Hdr_t*)(&frame)->data;
					if(packet->nextHdr == htons(0x06)){
						tcpsegment* cursegment = (tcpsegment*)(packet)->headers;
						if(cursegment->SYN == 1){
							void *key = memdup(&cursegment->srcPort,16);
							cookie *insert = malloc(sizeof(cookie));
							insert->localPort = memdup(&cursegment->srcPort,16);
							insert->remotePort = memdup(&cursegment->dstPort,16);
							insert->remoteAddr = memdup(&packet->dst,16);
							htinsert(tcphash,key,16,insert);
						}
					}
				}			
				struct sockaddr* addr = htfind(hasht, frame.dst, 6);
				if(addr != NULL){
					//addr = &bcaddr;

        	if(-1 == sendto(sock, &frame, rdct, 0,
                            	addr, sizeof(addr))){
        		perror("sendto");
					}
				}
			}
    }
    else if(FD_ISSET(in, &rdset) || FD_ISSET(out,&rdset)) {
			sock = FD_ISSET(in, &rdset) ? in : out;
			
			frame_t frame;
			struct sockaddr_in from;
			socklen_t flen = sizeof(from);

			ssize_t rdct = recvfrom(in, &frame,sizeof(frame_t), 0,
															(struct sockaddr*)&from,&flen);
		  if(rdct < 0) {
  			perror("recvfrom");
  		}
			else{
				if(!isspecialmac(frame.src)){
					if(hthaskey(hasht, frame.src, 6)){
						memcpy(htfind(hasht, frame.src, 6),
									&from, sizeof(struct sockaddr_in));
					}
					else{
						void* key = memdup(frame.src, 6);
						void* val = memdup(&from, 
																	sizeof(struct sockaddr_in));
						htinsert(hasht, key, 6, val);
					}
				}

				if(frame.type == htons(0x86DD)){
					ipv6Hdr_t *packet = (ipv6Hdr_t*)(&frame)->data;
					if(packet->nextHdr == htons(0x06)){
						tcpsegment* cursegment = (tcpsegment*)(packet)->headers;
						if(hthaskey(tcphash,&cursegment->dstPort,16)){
					  	if(-1 == write(tap, &frame, rdct))
    						perror("write");
						}
					}
				}
				else{	
			  	if(-1 == write(tap, &frame, rdct)) {
    					perror("write");
 		 			}
				}
      }
    maxfd = mkfdset(&rdset, tap, in, out, 0);
    }
	}
	htfree(hasht);
}

static void* memdup(void* p, size_t s){
	void *n = malloc(s);
	if(n != NULL)
		memcpy(n, p, s);
	return n;
}

static bool isspecialmac(unsigned char* mac){
	static const char mcast [] = {0x33, 0x33};
	static const char bcast [] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	return (memcmp(mac, mcast, 2) == 0 || memcmp(mac, bcast, 6) == 0);
}

static void daemonize(hashtable conf){
	daemon(0,0);
	if(hthasstrkey(conf,PID)){
		FILE *pidfile = fopen(htstrfind(conf,PID),"w");
		if(pidfile != NULL){
			fprintf(pidfile,"%d\n",getpid());
			fclose(pidfile);
		}
	}
}
