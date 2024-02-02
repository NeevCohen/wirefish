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
		TCPFrame frame = sniffer.read_next_tcp_frame();
		
		if (frame.src_ip_str != "1.1.1.1" && frame.dst_ip_str != "1.1.1.1") {
			continue;
		}

		std::cout << "================\n";
		std::cout << frame.src_ip_str << " -> " << frame.dst_ip_str << "\n";
		std::printf("%hu -> %hu\n", frame.tcp_sport, frame.tcp_dport);
		if (frame.tcp_header->th_flags & TH_SYN) {
			std::cout << "SYN ";
		}
		if (frame.tcp_header->th_flags & TH_FIN) {
			std::cout << "FIN ";
		}
		if (frame.tcp_header->th_flags & TH_ACK) {
			std::cout << "ACK ";
		}
		if (frame.tcp_header->th_flags & TH_PUSH) {
			std::cout << "PUSH ";
		}
		if (frame.tcp_header->th_flags & TH_RST) {
			std::cout << "RESET ";
		}
		std::cout << "\n";
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
