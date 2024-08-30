#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdexcept>
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>

#include "capture.h"
#include "ip_packet.h"
#include "ethernet_frame.h"


void load_ip_address(uint8_t *ip, size_t ip_len, std::vector<uint8_t>& vec) {
  for (size_t i = 0; i < ip_len; i++) {
    vec.push_back(*(ip + i));
  }
}


IPPacket::IPPacket(EthernetFrame& ethernet): ethernet(ethernet) {
  switch (ethernet.network_protocol) {
    case NetworkProtocol::IPv4:
      init_v4();
      break;
    case NetworkProtocol::IPv6:
      init_v6();
      break;
    default:
      std::cerr << "Cannot initialize IPPacket from unkown network protocol (" << (uint16_t)ethernet.network_protocol << ")" << std::endl;
      break;
  }
}


void IPPacket::init_v4() {
  version = IPVersion::V4;
  ip_header = (struct ip*)ethernet.ethernet_data;
  ip_data = (char*)ip_header + (ip_header->ip_hl * 4); // ip_hl specifies the length of the header in 32 bit words
  load_ip_address((uint8_t*)&ip_header->ip_src.s_addr, 4, src_ip);
  load_ip_address((uint8_t*)&ip_header->ip_dst.s_addr, 4, dst_ip);
  src_ip_str = parse_ip_address(src_ip);
  dst_ip_str = parse_ip_address(dst_ip);

  switch (ip_header->ip_p) {
    case IPPROTO_TCP:
      transport_protocol = TransportProtocol::TCP;
      break;
    case IPPROTO_UDP:
      transport_protocol = TransportProtocol::UDP;
      break;
    default:
      transport_protocol = TransportProtocol::UNKNOWN;
  }
}


void IPPacket::init_v6() {
  version = IPVersion::V6;
  ip6_header = (struct ip6_hdr*)ethernet.ethernet_data;
  load_ip_address((uint8_t*)&ip6_header->ip6_src, 12, src_ip);
  load_ip_address((uint8_t*)&ip6_header->ip6_dst, 12, dst_ip);
  src_ip_str = parse_ip_address(src_ip);
  dst_ip_str = parse_ip_address(dst_ip);

  ip_data = (char*)ip6_header + ip6_header_len;
  uint8_t next_header = ip6_header->ip6_nxt;
  struct ip6_ext *ext = (struct ip6_ext*)ip_data;
  bool done = false;

  while (!done) {
    switch (next_header) {
      case IPPROTO_TCP:
        transport_protocol = TransportProtocol::TCP;
        done = true;
        break;
      case IPPROTO_UDP:
        transport_protocol = TransportProtocol::UDP;
        done = true;
        break;
      case IPPROTO_HOPOPTS:
      case IPPROTO_ROUTING:
      case IPPROTO_FRAGMENT:
      case IPPROTO_AH:
      case IPPROTO_ESP:
      case IPPROTO_DSTOPTS:
        ip_data += ext->ip6e_len + 8;  // The length does not include the first 8 octets
        ext = (struct ip6_ext*)ip_data;
        next_header = ext->ip6e_nxt;
        break;
      default:
        transport_protocol = TransportProtocol::UNKNOWN;
        done = true;
        break;
    }
  }
}


std::string parse_ip_address(const std::vector<uint8_t>& ip) {
  int net_family = ip.size() == 4 ? AF_INET : AF_INET6;
  int addr_strlen = ip.size() == 4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
  char addr_str[INET6_ADDRSTRLEN];

  if (inet_ntop(net_family, ip.data(), addr_str, addr_strlen) == nullptr) {
    throw std::runtime_error("Invalid ip address"); 
  }
  return addr_str;
}

