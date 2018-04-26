int num1=0;

void handle_transmit_packet_port(const u_char* packet, const struct pcap_pkthdr * header, char* port, pcap_dumper_t* file){
	num_packets++;
	num1++;
	print_tcp_packet(packet, header);
	if (num1>=30){
		pcap_dump_flush(file);
		num1=0;
	}
	pcap_dump((u_char*)file, header, packet);
}

int num2=0;

void handle_receive_packet_port(const u_char* packet, const struct pcap_pkthdr *header, char* port, pcap_dumper_t* file){
	num_packets++;
	num2++;
	print_tcp_packet(packet, header);
	if (num2>=30){
		pcap_dump_flush(file);
		num2=0;
	}
	pcap_dump((u_char*)file, header, packet);
}

int num3=0;

void handle_packet_other_port(const u_char* packet, const struct pcap_pkthdr *header, pcap_dumper_t* file){
	printf("%s\n","I'm the wrong packet");
	num3++;
	if(num3 >= 30){
		pcap_dump_flush(file);
		num3=0;
	}
	pcap_dump((u_char*)file, header, packet);
}
