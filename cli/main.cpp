#include <iostream>
#include "sniffer.h"

int main() { 
	SnifferOptions opts {.interface_name = "en0"};
	Sniffer sniffer(opts);
	sniffer.attach_bpf();
	while (true) {
		Packet packet = sniffer.read_next_packet();
		struct ether_header *ethernet_header = (struct ether_header *)packet.data.get();
		std::printf("Ethernet source host %x:%x:%x:%x:%x:%x\n", 
					 ethernet_header->ether_shost[0], 
					 ethernet_header->ether_shost[1], 
					 ethernet_header->ether_shost[2], 
					 ethernet_header->ether_shost[3], 
					 ethernet_header->ether_shost[4], 
					 ethernet_header->ether_shost[5]
		);
		std::printf("Ethernet destination host %x:%x:%x:%x:%x:%x\n", 
					 ethernet_header->ether_dhost[0], 
					 ethernet_header->ether_dhost[1], 
					 ethernet_header->ether_dhost[2], 
					 ethernet_header->ether_dhost[3], 
					 ethernet_header->ether_dhost[4], 
					 ethernet_header->ether_dhost[5]
		);
	}
	return 0;
}
