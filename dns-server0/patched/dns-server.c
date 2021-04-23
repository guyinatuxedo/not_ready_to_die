/***
   * dns-server.c
   * Authors: Aditya Geria, Monisha Jain, Jeevana Lagisetty
   * Version 1.0.4 (April 1, 2016)
   * Fixed debug information, cleaned up messages shown
   * Host a simple DNS server which will resolve hosts from a given
   * hosts.txt file, and provide an IP address.
  **/

#include "dns.h"
#include <netdb.h>
#include <ctype.h>

#define BUFSIZE 2048
#define INVALID 0

struct host* hosts;	//(address, host name) struct
struct sockaddr_in remaddr;     // remote address
socklen_t addrlen = sizeof(remaddr);     // length of addresses 

int main(int argc, char **argv)
{
        int recvlen;  // # bytes received 
        int fd;       // our socket 
        
        char recvbuf[BUFSIZE];   // receive buffer 
	struct sockaddr_in myaddr;      // our address

        int port = 12345;
        char* hostfile;
       
	hosts = (struct host*) malloc(sizeof(struct host)*50); //allowing max of 50 hosts on the system

	if((argc+1) % 2 != 0 || argc == 1) {
		printf("Invalid number of argments. Use only -p and -f\n");
		exit(0);
	}

	if(argc > 5) {
		printf("Invalid number of argments. Use only -p and -f\n");
                exit(0);
	}

        if(argc > 0) {
                int i = 0;
                for(i = 0; i < argc; i++) {
                        if(argv[i][0] == '-' && argv[i][1] == 'p') {
                                port = atoi(argv[i+1]);
                        }
                        if(argv[i][0] == '-' && argv[i][1] == 'f') {
                                hostfile = argv[i+1];
                        }
                }
	}
	
        FILE* file = fopen(hostfile, "r");
	if(!file) {
		printf("No host file provided, use -f to provide a hosts file\n");
		exit(0);
	}

	//DEBUG - IGNORE
        //printf("port %d host files %s\n", port, hostfile);

        char addr[15];
        char name[253];
        int i = 0;

        /* look through the file and create (address, hostname) n-tuples
            store them in a hosts structure at the i-th element */
        while(!feof(file) && i <= 50) {
                if(fscanf(file, "%s ", addr) == 1) {
                        if(addr[0] == '#') {
                                fscanf(file, "\n");
                        }
                        else {
                                if(fscanf(file, "%s\n", name) == 1) {
                                    	printf("addr %s\t name: %s\n", addr, name);
                                    	strcpy(hosts[i].address, addr);
                                    	strcpy(hosts[i].name, name);
                                    	
					//DEBUG - IGNORE
					//printf("hosts addr: %s\t hosts name: %s\n", hosts[i].address, hosts[i].name);
                                }

                                i++;
                        }
                }
        }

        /* create a UDP socket */

        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
                perror("cannot create socket\n");
                return 0;
        }

        /* bind the socket to any valid IP address and a specific port */

        memset((char *)&myaddr, 0, sizeof(myaddr));
        myaddr.sin_family = AF_INET;
        myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        myaddr.sin_port = htons(port);

        if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
                perror("bind failed");
                return 0;
        }

        for(;;) {
                printf("==WAITING ON PORT %d==\n", port);
                recvlen = recvfrom(fd, recvbuf, BUFSIZE, 0, (struct sockaddr *)&remaddr, &addrlen);
                printf("received %d bytes\n", recvlen);
	
		//DEBUG - IGNORE
		//dump(recvbuf, recvlen); //debugging dump

		process_request(recvbuf, fd); //main method which handles resolving a query

                /*if((sendto(fd, recvbuf, BUFSIZE, 0, (struct sockaddr *)&remaddr, addrlen)) < 0) {
                        printf("Failed to send, line %d\n", __LINE__);
                        exit(1);
                }*/

        }


}

/**
 * @Method process_request
 * @param recvbuf - datagram packet received
 * @param fd - file descriptor, for sendto
 * Given a datagram, parse it accordingly, format a response
 * And send it back to the client in accordance with DNS
 * Protocol standards
 */
void process_request (void* recvbuf, int fd) {

        char* foundaddr;
        int i = 0;
        unsigned int addr;
	int querylen;

        dns_header* header = (dns_header*) recvbuf;
       
	//DEBUG - IGNORE
	//printf("id: %d\n", header->id);
        
	if(header->qr == 0) {
                printf("Correct query field - identified question\n");
                printf("Query count: %d\n", htons(header->qd_count));

                char* query = (char*)recvbuf + sizeof(dns_header); //gets the query name
                char name[256];
                char* namep = name;
                uint8_t len;
                unsigned int bytes_recieved = 0;
		int found = 0; //default 0 not found
	       	querylen = strlen(query);

		//creates the position for the second query
		char* ansname = (char*)recvbuf + sizeof(dns_header) + querylen + 1 + sizeof(dns_question);
		
		printf("Query length: %d\n", querylen);
		memcpy(ansname, query, querylen + 1);
		
		//DEBUG - IGNORE
		//printf("ansname; %s\n", ansname);
		

		//reading the query name
                while((int)*query != 0) {
                    len = (uint8_t)*query;
                    printf("len (1): %d\n", len);
                    if ((bytes_recieved + len) >= 256) {
                        return;
                    }
                    memcpy(namep, query + 1, len);
                    bytes_recieved += len;
                    namep += len;
                    query += len + 1;
                    len = (uint8_t)*query;
                    if(len != 0) {
                        if ((bytes_recieved + len) >= 256) {
                            return;
                        }
                            *namep++ = '.';
                            memcpy(namep, query + 1, len);
                            bytes_recieved += len;
                    }
                    *namep = 0;
                }

		//DEBUG - IGNORE
		//dump(ansname, querylen);
		//printf("query name: %s\n", name);

		for(i = 0; i < 50; i++) {
                        if(strcmp(hosts[i].name, name) == 0) {
                                printf("Address = %s\n", hosts[i].address);
                                foundaddr = hosts[i].address;
				found = 1;
                                break;
                        }
                }

		if(found == 0) {

			header->qr = 1;
                	header->aa = 1;
	                header->tc = 0;
        	        header->ra = 0;
			header->qd_count = 0;
                	header->rcode = 3; //not found error code;

			//no need to add answer record, or query

			if((sendto(fd, recvbuf, sizeof(dns_header) + querylen, 0, 
				(struct sockaddr*)&remaddr, addrlen)) < 0) {
                        	printf("Failed to send, line %d\n", __LINE__);
                        	exit(1);
                	}

			return;
		}

                addr = htonl(ip_to_int(foundaddr));
		//DEBUG
		//printf("%08x addr\n", addr);

	        /* Start modifying the header to be a response packet */
	
                header->qr = 1;
                header->aa = 1;
                header->tc = 0;
                header->ra = 0;
                header->rcode = 0;
		header->an_count = htons(1);

		//set query to be the end of ansname		
		query = ansname + querylen;
	
                //create a response record struct and append to query name
                dns_rrhdr* rrhdr = (dns_rrhdr*)(query + 1);
                rrhdr->type = htons(1);
                rrhdr->class = htons(1);
                rrhdr->ttl = htonl(20);
                rrhdr->data_len = htons(4);

                memcpy(query + 1 +sizeof(dns_rrhdr) , &addr, 4); //add the IP to the end of the datagram

		//DEBUG - IGNORE
		//dump(recvbuf,  (query + 1 + sizeof(dns_rrhdr)+ 4 - ((char*)recvbuf)) );

		//memcpy(((char*)recvbuf)+sizeof(query), rrhdr, sizeof(rrhdr));
		if((sendto(fd, recvbuf, (query + 1 + sizeof(dns_rrhdr) + 4 - ((char*)recvbuf)) , 0, (struct sockaddr *)&remaddr, addrlen)) < 0) {
                        printf("Failed to send, line %d\n", __LINE__);
                        exit(1);
                }
                
        }
        else {

		querylen = 32;
                //in case of a code4
		header->qr = 1;
                header->aa = 1;
                header->tc = 0;
                header->ra = 0;
		header->qd_count = 0;
                header->rcode = 4; //not implemented

                //no need to add answer record, or query
                if((sendto(fd, recvbuf, sizeof(dns_header) + querylen, 0,
                                (struct sockaddr*)&remaddr, addrlen)) < 0) {
	                printf("Failed to send, line %d\n", __LINE__);
       	                exit(1);
                }

                return;
        }
}


/**
 * @Method ip_to_int
 * @param ip - IP Address in string form
 * Given an IP Address string such as "1.2.3.4", convert it
 * into an unsigned int to transfer over a network
 */
unsigned int ip_to_int (const char * ip)
{
    /* The return value. */
    unsigned v = 0;
    /* The count of the number of bytes processed. */
    int i;
    /* A pointer to the next digit to process. */
    const char * start;

    start = ip;
    for (i = 0; i < 4; i++) {
    	/* The digit being processed. */
        char c;
        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            /* Stop at '.' if we are still parsing
               the first, second, or third numbers. If we have reached
               the end of the numbers, allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return INVALID;
            }
        }
        if (n >= 256) {
            return INVALID;
        }
        v *= 256;
        v += n;
    }
    return v;
}

/**
 * @Method dump
 * @param buf - thing to view/dump
 * @param len - length of buf
 * Shows contents of (buf) in bitwise manner
 */
void dump (char* buf, int len) {
	int i = 0;
	//int len = strlen(buf);
        for(i=0; i < len; ++i)
        	printf("%02x ", buf[i]);  // dump hex values
        printf("\n");

        for(i=0; i < len; ++i) {
                if(isprint(buf[i]))
                        printf("’%c'  ", buf[i]);  // dump a character if it’s printable
                else
                        printf("0x%02x ", buf[i]);  // else dump a hex value
	}
	printf("\n");
	return;
}
