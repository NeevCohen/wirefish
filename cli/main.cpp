#include "sniffer.h"
#include <arpa/inet.h>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <unistd.h>

void print_ip(Sniffer &sniffer, int t)
{
	// for (int i = 0; i < 1; i++) {
	/*
	std::printf("%d is reading the next ip packet\n", t);
IPPacket packet = sniffer.read_next_ip_packet();
	std::printf("%d read a packet\n", t);
std::cout << "================\n";
char s[INET_ADDRSTRLEN] = {0};
char d[INET_ADDRSTRLEN] = {0};
inet_ntop(AF_INET, &(packet.ip_header->ip_src.s_addr), s, INET_ADDRSTRLEN);
inet_ntop(AF_INET, &(packet.ip_header->ip_dst.s_addr), d, INET_ADDRSTRLEN);
	std::printf("%x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x\n",
							packet.ethernet_header->ether_shost[0],
							packet.ethernet_header->ether_shost[1],
							packet.ethernet_header->ether_shost[2],
							packet.ethernet_header->ether_shost[3],
							packet.ethernet_header->ether_shost[4],
							packet.ethernet_header->ether_shost[5],
							packet.ethernet_header->ether_dhost[0],
							packet.ethernet_header->ether_dhost[1],
							packet.ethernet_header->ether_dhost[2],
							packet.ethernet_header->ether_dhost[3],
							packet.ethernet_header->ether_dhost[4],
							packet.ethernet_header->ether_dhost[5]
	);
std::printf("%d %s -> %s | id - %d\n", t, s, d, packet.ip_header->ip_id);
	*/

	EthernetFrame frame = sniffer.read_next_ethernet_frame(t);
	std::cout << "================\n";
	std::printf("%d: %x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x - %lu\n",
				t,
				frame.ethernet_header->ether_shost[0],
				frame.ethernet_header->ether_shost[1],
				frame.ethernet_header->ether_shost[2],
				frame.ethernet_header->ether_shost[3],
				frame.ethernet_header->ether_shost[4],
				frame.ethernet_header->ether_shost[5],
				frame.ethernet_header->ether_dhost[0],
				frame.ethernet_header->ether_dhost[1],
				frame.ethernet_header->ether_dhost[2],
				frame.ethernet_header->ether_dhost[3],
				frame.ethernet_header->ether_dhost[4],
				frame.ethernet_header->ether_dhost[5],
				frame.buffer_size);
	//}
	std::printf("%d finished capture\n", t);
}

int main()
{
	
  if (getuid()) {
	std::cerr << "Please run as root user\n";
	exit(EXIT_FAILURE);
  }
	

	SnifferOptions opts{.interface_name = "en0"};
	Sniffer sniffer(opts);
	sniffer.attach_bpf();

	/*
  for (int i = 0; i < 20; i++) {
	IPPacket packet = sniffer.read_next_ip_packet();
	std::cout << "================\n";
	char s[INET_ADDRSTRLEN] = {0};
	char d[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &(packet.header->ip_src.s_addr), s, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(packet.header->ip_dst.s_addr), d, INET_ADDRSTRLEN);
	std::printf("%d: IP source host: %s\n", t, s);
	std::printf("%d: IP destination host: %s\n", t, d);
		*/
	/*
std::cout << "================\n";
	EthernetFrame frame = sniffer.read_next_ethernet_frame();
	std::printf("%x:%x:%x:%x:%x:%x\n",
			frame.ethernet_header->ether_shost[0],
			frame.ethernet_header->ether_shost[1],
			frame.ethernet_header->ether_shost[2],
			frame.ethernet_header->ether_shost[3],
			frame.ethernet_header->ether_shost[4],
			frame.ethernet_header->ether_shost[5]
	);
	std::printf("%x:%x:%x:%x:%x:%x\n",
			frame.ethernet_header->ether_dhost[0],
			frame.ethernet_header->ether_dhost[1],
			frame.ethernet_header->ether_dhost[2],
			frame.ethernet_header->ether_dhost[3],
			frame.ethernet_header->ether_dhost[4],
			frame.ethernet_header->ether_dhost[5]
	);
}
*/

	std::thread t1{&print_ip, std::ref(sniffer), 1};
	std::thread t2{&print_ip, std::ref(sniffer), 2};
	t1.join();
	t2.join();

	return 0;
}
