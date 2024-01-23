#include <cstdlib>
#include <iostream>
#include <memory>
#include <arpa/inet.h>
#include <stdexcept>
#include <unistd.h>
#include "sniffer.h"

int main() { 
	if (getuid()) {
		std::cerr << "Please run as root user\n";
		exit(EXIT_FAILURE);
	}

	SnifferOptions opts {.interface_name = "en0"};
	Sniffer sniffer(opts);
	sniffer.attach_bpf();
	while (true) {
		IPPacket packet = sniffer.read_next_ip_packet();
		std::cout << "================\n";
		char s[INET_ADDRSTRLEN] = {0};
		char d[INET_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET, &(packet.header->ip_src.s_addr), s, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(packet.header->ip_dst.s_addr), d, INET_ADDRSTRLEN);
		std::printf("IP source host: %s\n", s);
		std::printf("IP destination host: %s\n", d);
	}
	return 0;
}
