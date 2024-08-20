#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdexcept>
#include <iostream>

#include "capture.h"
#include "ip_packet.h"
#include "ethernet_frame.h"


void load_ip_address(uint32_t *ip, std::vector<uint8_t>& vec) {
  for (int i = 0; i < 4; i++) {
    vec.push_back(*((uint8_t*)ip + i));
  }
}


IPPacket::IPPacket(EthernetFrame& ethernet): ethernet(ethernet) {
  ip_header = (struct ip *)ethernet.ethernet_data;
  ip_data = (char*)ip_header + (ip_header->ip_hl * 4); // ip_hl specifies the length of the header in 32 bit words
  load_ip_address(&ip_header->ip_src.s_addr, src_ip);
  load_ip_address(&ip_header->ip_dst.s_addr, dst_ip);
  src_ip_str = parse_ip_address(src_ip);
  dst_ip_str = parse_ip_address(dst_ip);

  if (ip_header->ip_p == IPPROTO_TCP) {
    transport_protocol = TransportProtocol::TCP;
  } else if (ip_header->ip_p == IPPROTO_UDP) {
    transport_protocol = TransportProtocol::UDP;
  } else {
    transport_protocol = TransportProtocol::UNKNOWN;
  }
}


std::string parse_ip_address(const std::vector<uint8_t>& ip) {
  char addr_str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, ip.data(), addr_str, INET_ADDRSTRLEN) == nullptr) {
    throw std::runtime_error("Invalid ip address"); 
  }
  return addr_str;
}

