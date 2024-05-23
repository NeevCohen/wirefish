#include "libsniff.h"
#include <cstdlib>
#include <iostream>
#include <thread>
#include <unistd.h>

void print_ip(Sniffer &sniffer)
{
  int i = 0;
  while (i < 10) {
    Capture cap = sniffer.read_next_capture();
    EthernetFrame ether(cap);
    if (ether.network_protocol == NetworkProtocol::UNKNOWN) {
      std::cout << "Unknown network protocol - 0x" << ntohs(ether.ethernet_header->ether_type) << "\n";
    } else if (ether.network_protocol == NetworkProtocol::ARP) {
      std::cout << "ARP\n";
    } else if (ether.network_protocol == NetworkProtocol::IPv4) {
      IPPacket ip(ether);
      std::printf("%s -> %s\n", ip.src_ip_str.c_str(), ip.dst_ip_str.c_str());
      if (ip.transport_protocol == TransportProtocol::TCP) {
        TCPFrame tcp(ip);
        std::printf("TCP - %hu -> %hu\n", tcp.tcp_sport, tcp.tcp_dport);
      } else if (ip.transport_protocol == TransportProtocol::UDP) {
        UDPDatagram udp(ip);
        std::printf("UDP - %hu -> %hu\n", udp.udp_sport, udp.udp_dport);
      }
    }
    std::cout << "====================\n";
    ++i;
  }
}

int main()
{
  if (getuid()) {
    std::cerr << "Please run as root user\n";
    exit(EXIT_FAILURE);
  }

  std::cout << "Sniffing...\n";

  SnifferOptions opts {.interface_name = "en0"};
  Sniffer sniffer(opts);
  sniffer.attach_bpf();

  std::thread t1{print_ip, std::ref(sniffer)};
  std::thread t2{print_ip, std::ref(sniffer)};
  t1.join();
  t2.join();

  return 0;
}
