#include "capture.h"
#include "libsniff.h"
#include "arg_parse.h"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <unistd.h>

int main(int argc, char **argv)
{
  if (getuid()) {
    std::cerr << "Please run as root user\n";
    exit(EXIT_FAILURE);
  }

  SnifferOptions opts {.interface_name = "en0"};
  Sniffer sniffer(opts);
  sniffer.attach_bpf();

  try {
    SniffingOptions sniffing_options = parse_args(argc, argv);
  } catch (std::invalid_argument& e) {
    std::cerr << "ERROR: \n\t";
    std::cerr << e.what() << "\n";
    return -1;
  }

  int i = 0;
  while (i < 10) {
    Capture cap = sniffer.read_next_capture();
    EthernetFrame ether(cap);
    if (ether.network_protocol == NetworkProtocol::UNKNOWN) {
      std::cout << "Unknown network protocol - 0x" << std::hex << ntohs(ether.ethernet_header->ether_type) << "\n";
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
    } else if (ether.network_protocol == NetworkProtocol::IPv6) {
      std::cout << "IPv6\n";
    }
    std::cout << "====================\n";
    ++i;
  }
  return 0;
}
