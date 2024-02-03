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
		UDPDatagram dgram = sniffer.read_next_udp_datagram();
		/*
		if (dgram.udp_dport != 8000) {
			i--;
			continue;
		}
		*/
		std::cout << "================\n";
		std::printf("%s -> %s\n", dgram.src_ip_str.c_str(), dgram.dst_ip_str.c_str());
		std::printf("%hu -> %hu\n", dgram.udp_sport, dgram.udp_dport);
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
	//std::thread t2{print_ip, std::ref(sniffer)};
	t1.join();
	//t2.join();

	return 0;
}
