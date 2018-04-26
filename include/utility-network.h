#include<arpa/inet.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<string.h>
#include<stdlib.h>
#include<stdio.h>
//#include "utility.h"

void inet_itoa(unsigned int ip_int, char* ip_ascii);

/* Structure for Ethernet headers */
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr {
   unsigned char ether_dest_addr[ETHER_ADDR_LEN]; // Destination MAC address
   unsigned char ether_src_addr[ETHER_ADDR_LEN];  // Source MAC address
   unsigned short ether_type; // Type of Ethernet packet
};

/* Structure for Internet Protocol (IP) headers */
struct ip_hdr {
   unsigned char ip_version_and_header_length; // version and header length combined
   unsigned char ip_tos;          // type of service
   unsigned short ip_len;         // total length
   unsigned short ip_id;          // identification number
   unsigned short ip_frag_offset; // fragment offset and flags
   unsigned char ip_ttl;          // time to live
   unsigned char ip_type;         // protocol type
   unsigned short ip_checksum;    // checksum
   unsigned int ip_src_addr;      // source IP address
   unsigned int ip_dest_addr;     // destination IP address
};

/* Structure for Transmission Control Protocol (TCP) headers */
struct tcp_hdr {
   unsigned short tcp_src_port;   // source TCP port
   unsigned short tcp_dest_port;  // destination TCP port
   unsigned int tcp_seq;          // TCP sequence number
   unsigned int tcp_ack;          // TCP acknowledgement number
   unsigned char reserved:4;      // 4-bits from the 6-bits of reserved space
   unsigned char tcp_offset:4;    // TCP data offset for little endian host
   unsigned char tcp_flags;       // TCP flags (and 2-bits from reserved space)
#define TCP_FIN   0x01
#define TCP_SYN   0x02
#define TCP_RST   0x04
#define TCP_PUSH  0x08
#define TCP_ACK   0x10
#define TCP_URG   0x20
   unsigned short tcp_window;     // TCP window size
   unsigned short tcp_checksum;   // TCP checksum
   unsigned short tcp_urgent;     // TCP urgent pointer
};

void decode_ethernet(const u_char *header_start) {
	int i;
	const struct ether_hdr *ethernet_header;

	ethernet_header = (const struct ether_hdr *)header_start;
	printf("[[  Layer 2 :: Ethernet Header  ]]\n");
	printf("[ Source: %02x", ethernet_header->ether_src_addr[0]);
	for(i=1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_src_addr[i]);

	printf("\tDest: %02x", ethernet_header->ether_dest_addr[0]);
	for(i=1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_dest_addr[i]);
	printf("\tType: %hu ]\n", ethernet_header->ether_type);
}

void decode_ip(const u_char *header_start) {
	const struct ip_hdr *ip_header;
	ip_header = (const struct ip_hdr *)header_start;
	char ip_addr[16];	
	memset(ip_addr, 0, 16);	
	
	printf("\t((  Layer 3 ::: IP Header  ))\n");
	
	inet_itoa(ip_header->ip_src_addr,ip_addr);
	printf("\t( Source: %s\t", ip_addr);
	
	memset(ip_addr, 0, 16);	
	inet_itoa(ip_header->ip_dest_addr, ip_addr);
	printf("\t( Type: %u\t", (u_int) ip_header->ip_type);
	printf("Dest: %s )\n", ip_addr);
	printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

u_int decode_tcp(const u_char *header_start) {
	u_int header_size;
	const struct tcp_hdr *tcp_header;

	tcp_header = (const struct tcp_hdr *)header_start;
	header_size = 4 * tcp_header->tcp_offset;
	
	printf("\t\t{{  Layer 4 :::: TCP Header  }}\n");
	printf("\t\t{ Src Port: %hu\t", ntohs(tcp_header->tcp_src_port));
	printf("Dest Port: %hu }\n", ntohs(tcp_header->tcp_dest_port));
	printf("\t\t{ Seq #: %u\t", ntohl(tcp_header->tcp_seq));
	printf("Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
	printf("\t\t{ Header Size: %u\tFlags: ", header_size);
	if(tcp_header->tcp_flags & TCP_FIN)
		printf("FIN ");
	if(tcp_header->tcp_flags & TCP_SYN)
		printf("SYN ");
	if(tcp_header->tcp_flags & TCP_RST)
		printf("RST ");
	if(tcp_header->tcp_flags & TCP_PUSH)
		printf("PUSH ");
	if(tcp_header->tcp_flags & TCP_ACK)
		printf("ACK ");
	if(tcp_header->tcp_flags & TCP_URG)
		printf("URG ");
	printf(" }\n");

	return header_size;
}

void inet_itoa(unsigned int ip_int, char *ip_ascii){
		
	unsigned int byte;
	char res[4];
	char buf[5][4];

	for (int i=0;i<4;i++){
		byte=ip_int>>(8*(3-i));
		byte=byte<<24;		
		byte=byte>>24;
		sprintf(res,"%u",byte);
		res[3]='\0';
		strcpy(buf[i],res);		
	}
	for (int i=0; i<4; i++){
		strcat(ip_ascii, buf[3-i]);
		if(i!=3)	strcat(ip_ascii,".");	
	}
	return;
}


void print_tcp_packet(const u_char* packet, const struct pcap_pkthdr *header){
	int tcp_header_length, total_header_size, pkt_data_len;
	u_char *pkt_data;
	
	printf("==== Got a %d byte packet ====\n", header->len);

	decode_ethernet(packet);
	decode_ip(packet+ETHER_HDR_LEN);
	tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr));

	total_header_size = ETHER_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_length;
	pkt_data = (u_char *)packet + total_header_size;  // pkt_data points to the data portion
	pkt_data_len = header->len - total_header_size;
	if(pkt_data_len > 0) {
		printf("\t\t\t%u bytes of packet data\n", pkt_data_len);
		dump(pkt_data, pkt_data_len);
	} else
		printf("\t\t\tNo Packet Data\n");

}






