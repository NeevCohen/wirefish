#include "capture.h"
#include "sniffer.h"
#include <arpa/inet.h>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

void print_ip(Sniffer &sniffer)
{
	for (int i = 0; i < 10; i++) {
		IPPacket pac = sniffer.read_next_ip_packet();
		
		std::cout << "================\n";
		char s[INET_ADDRSTRLEN];
		char d[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(pac.ip_header->ip_src.s_addr), s, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(pac.ip_header->ip_dst.s_addr), d, INET_ADDRSTRLEN);
		std::printf("%s -> %s\n", s, d);
	}
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


	std::thread t1{print_ip, std::ref(sniffer)};
	std::thread t2{print_ip, std::ref(sniffer)};
	t1.join();
	t2.join();

	return 0;
}
