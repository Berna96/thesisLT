#include<stdio.h>
#include<stdlib.h>
#include<pcap/pcap.h>
#include<signal.h>
#include<string.h>
#include<pthread.h>
#include<unistd.h>
#include "include/debug.h"
#include "include/scanfile.h"
#include "include/utility-network.h"
//#include "include/timesplit.h"
//#include "include/handle-packet.h"
//#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/wait.h>


pcap_t* pcap_handle;
int num_packets=0;
char errbuf[PCAP_ERRBUF_SIZE];
bpf_u_int32 net;
int time_reached=0;
int partition=0;
unsigned int minute=1;
unsigned int sec;
int f=0;
char argcomm[70];
pcap_dumper_t*** fileportp;
pcap_dumper_t** fileotherportp;
ports_info **portsp;
int pid;

struct args_loop{
	ports_info *ports;
	void (*callback_port_transmit)(const u_char*, const struct pcap_pkthdr *, char*, pcap_dumper_t*);
	void (*callback_port_receive)(const u_char*, const struct pcap_pkthdr *, char*, pcap_dumper_t*);
	void (*callback_other_port)(const u_char*, const struct pcap_pkthdr *, pcap_dumper_t*);
	struct bpf_program* bf_src_port;
	struct bpf_program* bf_dst_port;
	struct bpf_program bf_src_myip;
	struct bpf_program bf_dst_myip;
	pcap_dumper_t** fileport;
	pcap_dumper_t* fileotherport;
};
/*struct info_packet{
	const u_char *packet;
	const struct pcap_pkthdr *header;
	char* port;
};*/

void break_time(int);

void initilize_filter_port(ports_info *, const char*, struct bpf_program *);

void pcap_fatal(const char *failed_in, const char *errbuf);

void killhandler(int);	

void apply_filter(u_char *, const struct pcap_pkthdr *, const u_char *);	

void send_and_flush_file(pcap_dumper_t **, pcap_dumper_t **, ports_info *);

void handle_transmit_packet_port(const u_char*, const struct pcap_pkthdr *, char*, pcap_dumper_t*);

void handle_receive_packet_port(const u_char*, const struct pcap_pkthdr *, char*, pcap_dumper_t*);

void handle_packet_other_port(const u_char*, const struct pcap_pkthdr*, pcap_dumper_t*);

void handle_child(int signum);

void pcap_open_file_port(pcap_dumper_t **, pcap_dumper_t **, ports_info *);


int main(int argc, char* argv[]){

/*dichiarazione variabili e allocazione*/
FILE *portlist;
const char* FILENAME="./portlist.conf";
ports_info *ports;
const char* VERSION;
char* device_name;
bpf_u_int32 mask;
char filter_expr[100];
int loop_stat;
const int MAX_DIM=2048;
int timeout=0;
int promisc=0;
int num_ports;
pcap_if_t *my_device;
pcap_if_t *first_element_pointer;
pcap_dumper_t** fileport;
pcap_dumper_t* fileotherport;
struct bpf_program* bf_src_port;
struct bpf_program* bf_dst_port;
struct bpf_program bf_src_myip;
struct bpf_program bf_dst_myip;
struct bpf_program bf_tcp;
struct args_loop* args;
char* pidstr;

signal(SIGINT, killhandler);	//registra il segnale
signal(SIGALRM, break_time);
//signal(SIGCHLD, handle_child);
/*pidstr=getenv("PID");
pdebug(pidstr);
printf("%s\n", pidstr);
fflush(stdout);
pid=atoi(pidstr);
printf("%s\n", pidstr);
debug();
*/
if (argc<2)	usage(argv[0]);
else 	strncpy(argcomm, argv[1], 70);
pid=atoi(argcomm);

/*apri e scannerizza file*/			
portlist = fopen(FILENAME,"r");		
if (portlist == NULL){		
	fprintf(stderr,"Problem with opening file: %s\n", FILENAME);
	fflush(stderr);		
	exit(1);		
}	 		  
ports=scan_file(portlist);
fclose(portlist);	

portsp=&ports;		 
/**/

//INUTILE
VERSION = pcap_lib_version();
printf("Version : %s\n", VERSION);

/*inizializzazione pcap*/
if (pcap_findalldevs(&first_element_pointer, errbuf)==-1)	pcap_fatal("pcap_findalldevs",errbuf);
my_device=first_element_pointer;
if (my_device == NULL){
	perror("No such interface to listen\n");
	fflush(stderr);
	return 1;
}else if (my_device->flags==PCAP_IF_LOOPBACK){
	printf("%s\n","The first interface is not a good interface.\nTrying something else..");
	int no_good_interface=1;
	pcap_if_t *next_dev=my_device->next;
	while(next_dev!=NULL){
		if (next_dev->flags!=PCAP_IF_LOOPBACK){
			my_device=next_dev;
			no_good_interface=0;
			break;
		}
		next_dev=next_dev->next;
	}
	if (no_good_interface){	
		printf("%s\n","No such good interface to listen. Exiting...");
		return 1;
	}
}

device_name=my_device->name;

//device_name=pcap_lookupdev(errbuf);

if (pcap_lookupnet(device_name,&net,&mask,errbuf)==-1)	pcap_fatal("pcap_lookupnet",errbuf);
printf("Sniffing on %s\n", device_name);
pcap_handle = pcap_open_live(device_name,MAX_DIM,promisc,timeout,errbuf);
if(pcap_handle==NULL)	pcap_fatal("pcap_open_live",errbuf);
//if(pcap_set_promisc(pcap_handle,0)==PCAP_ERROR_ACTIVATED)	pcap_fatal("pcap_set_promisc",errbuf);
//pcap_setdirection(pcap_handle, PCAP_D_INOUT);

int datalink=pcap_datalink(pcap_handle);			
if((datalink!=DLT_EN10MB)/* || (datalink!=DLT_IEE802_11) || (datalink!=DLT_FFDI) || (datalink!=DLT_PPP_ETHER) || (datalink!=DLT_NULL) || (datalink!=DLT_PPP)*/){
		printf("%s\n","No right interface installed on this computer.\nInterfaces supported: Ethernet, Wi-Fi 802.11, FDDI, PPPoE, BSD Loopback, Point to Point(Dial-up)\n");
		pcap_fatal("pcap_datalink",errbuf);
}			
/**/	

num_ports=ports->num_ports;
bf_src_port=malloc(sizeof(struct bpf_program)*num_ports);
bf_dst_port=malloc(sizeof(struct bpf_program)*num_ports);
initilize_filter_port(ports, "src", bf_src_port);
initilize_filter_port(ports, "dst", bf_dst_port);

char ip_expr[100];
char my_ip[INET_ADDRSTRLEN];
char my_ipv6[INET6_ADDRSTRLEN];
char hostname[1024];
hostname[1023]='\0';
gethostname(hostname, 1023);

for(pcap_addr_t *a=my_device->addresses; a!=NULL; a=a->next){
	if (a->addr->sa_family == AF_INET){
		inet_ntop(AF_INET,(const void*)&(((struct sockaddr_in*)a->addr)->sin_addr), my_ip, INET_ADDRSTRLEN);
		if (my_ip==NULL){ printf("%s\n", "No ipv4"); return 1;}
	}else if (a->addr->sa_family == AF_INET6){
		inet_ntop(AF_INET6,(const void*)&(((struct sockaddr_in6*)a->addr)->sin6_addr), my_ipv6, INET6_ADDRSTRLEN);
		if (my_ipv6==NULL){ printf("%s\n", "No ipv6"); return 1;}
	}
} 
printf("My host name: %s\n", hostname);
printf("My ipv4: %s\n",my_ip);
printf("My ipv6: %s\n",my_ipv6);
char tcp_expr[50];
//sprintf(tcp_expr, "tcp and host %s", hostname);
sprintf(tcp_expr, "tcp");
//sprintf(ip_expr, "src host %s", hostname);
sprintf(ip_expr, "ip src host %s", my_ip);
if (pcap_compile(pcap_handle,&bf_tcp, tcp_expr,0,net)==-1)	pcap_fatal("pcap_compile",errbuf);	
if (pcap_setfilter(pcap_handle,&bf_tcp)==-1)	pcap_fatal("pcap_setfilter",errbuf);	
if (pcap_compile(pcap_handle,&bf_src_myip,ip_expr,0,net)==-1)	pcap_fatal("pcap_compile",errbuf);
memset(ip_expr,0,50);
sprintf(ip_expr, "ip dst host %s", my_ip);
if (pcap_compile(pcap_handle,&bf_dst_myip,ip_expr,0,net)==-1)	pcap_fatal("pcap_compile",errbuf);

fileport=(pcap_dumper_t**)malloc(sizeof(pcap_dumper_t*)*num_ports);
fileportp=&fileport;
fileotherportp=&fileotherport;
pcap_open_file_port(fileport, fileotherportp, ports);

//da trasferire in un altro file
args=malloc(sizeof(struct args_loop));
args->ports=ports;
args->bf_src_port=bf_src_port;
args->bf_dst_port=bf_dst_port;
args->bf_src_myip=bf_src_myip;
args->bf_dst_myip=bf_dst_myip;
args->fileport=fileport;
args->fileotherport=fileotherport;
args->callback_port_transmit=handle_transmit_packet_port;
args->callback_port_receive=handle_receive_packet_port;
args->callback_other_port=handle_packet_other_port;

//alarm
sec=60*minute;
alarm(sec);

loop_stat=pcap_loop(pcap_handle, -1, apply_filter, (u_char*) args);		

pcap_freecode(&bf_tcp);	
pcap_close(pcap_handle);		
pcap_freealldevs(my_device);

printf("\nNumero di pacchetti: %d\n", num_packets);
printf("Processo terminato correttamente\n");
fflush(stdout);
return 0;
}



/*	functions	*/

void pcap_fatal(const char *failed_in, const char *errbuf){
	fprintf(stderr,"[DEBUG]Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}

void break_time(int signum){
	partition++;
	//time_reached=1;
	printf("Time stop: %u minute\n", minute);
	alarm(sec);
	send_and_flush_file(*fileportp, fileotherportp, *portsp);
}

void killhandler(int signum){
	pcap_breakloop(pcap_handle);
}

void handle_child(int signum){
	int status;
	wait(&status);
	if (status!=0){
		perror("Problem with transferring file: exiting program..\n");
		exit(3);
	}else{
		printf("%s\n","Transfer file complete");
	}
}

void initilize_filter_port(ports_info* ports, const char* str, struct bpf_program* bf ){
	char init_expr[10];
	char filter_expr[30];
	if (strcmp(str,"src")==0){
		strcpy(init_expr,"src port");
	}else{
		strcpy(init_expr,"dst port");
	}
	for (int i=0; i<ports->num_ports;i++){
		memset(filter_expr,0,20);
		sprintf(filter_expr, "%s %s", init_expr, *(ports->port+i));
		if (pcap_compile(pcap_handle,bf+i,filter_expr,0,net)==-1)   pcap_fatal("pcap_compile",errbuf);
	}
}

void pcap_open_file_port(pcap_dumper_t **fileport, pcap_dumper_t **fileotherportp, ports_info *ports){
	char filename[30];
	pcap_dumper_t* tmp;
	for (int i=0; i<ports->num_ports; i++){
		sprintf(filename, "./pcapfiles/%d/port%s.pcap", f, *(ports->port+i));				
		tmp=pcap_dump_open(pcap_handle, filename);
		*(fileport+i)=tmp;	
	}
	sprintf(filename, "./pcapfiles/%d/portother.pcap", f);
	*fileotherportp=pcap_dump_open(pcap_handle, filename);
}

void apply_filter(u_char *arguments, const struct pcap_pkthdr *header, const u_char *packet){
	
	struct args_loop* args=(struct args_loop*)arguments;
	ports_info* ports=args->ports;
	int other_port_flag=1;
	if (pcap_offline_filter(&(args->bf_src_myip),header,packet)){
		//args->callback_port_transmit(packet,header,"8000", *(args->fileport));
		//other_port_flag=0;
		for(int i=0; i<ports->num_ports; i++){
			if (pcap_offline_filter(args->bf_src_port+i,header,packet)){
				args->callback_port_transmit(packet,header,*(ports->port+i), *(args->fileport+i));
				other_port_flag=0;
				break;
			}	
		}
	}else if(pcap_offline_filter(&(args->bf_dst_myip),header,packet)){
		//args->callback_port_receive(packet,header,"8000", *(args->fileport));
		//other_port_flag=0;
		for(int i=0; i<ports->num_ports; i++){
			if (pcap_offline_filter(args->bf_dst_port+i,header,packet)){
				args->callback_port_receive(packet,header,*(ports->port+i), *(args->fileport+i));
				other_port_flag=0;
				break;
		}	
		}
	}			
	/**/
	if (other_port_flag)	args->callback_other_port(packet, header, args->fileotherport);
	
}

void send_and_flush_file(pcap_dumper_t **fileport, pcap_dumper_t **fileotherportp, ports_info *ports){
	
	for (int i=0; i<ports->num_ports; i++){
		pcap_dump_flush(*(fileport+i));
		pcap_dump_close(*(fileport+i));	
	}
	pcap_dump_flush(*fileotherportp);
	pcap_dump_close(*fileotherportp);
	
	kill(pid,SIGUSR1);
	
	f=!f;
	pcap_open_file_port(fileport, fileotherportp, ports);
}

void handle_transmit_packet_port(const u_char* packet, const struct pcap_pkthdr * header, char* port, pcap_dumper_t* file){
	num_packets++;
	printf("Got a transmitted packet: lenght %u\n", header->len);
	print_tcp_packet(packet, header);
	pcap_dump((u_char*)file, header, packet);
}

void handle_receive_packet_port(const u_char* packet, const struct pcap_pkthdr *header, char* port, pcap_dumper_t* file){
	num_packets++;
	printf("Got a received packet: lenght %u\n", header->len);
	print_tcp_packet(packet, header);
	pcap_dump((u_char*)file, header, packet);
}

void handle_packet_other_port(const u_char* packet, const struct pcap_pkthdr *header, pcap_dumper_t* file){
	printf("%s\n","I'm the wrong packet");
	//print_tcp_packet(packet, header);
	pcap_dump((u_char*)file, header, packet);
}
