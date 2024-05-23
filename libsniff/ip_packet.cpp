#include "arpa/inet.h"

#include "capture.h"
#include "ip_packet.h"
#include "ethernet_frame.h"

IPPacket::IPPacket(EthernetFrame& ethernet): ethernet(ethernet) {
  ip_header = (struct ip *)ethernet.ethernet_data;
  ip_data = (char*)ip_header + (ip_header->ip_hl * 4); // ip_hl specifies the length of the header in 32 bit words
  char src_addr_str[INET_ADDRSTRLEN];
  char dst_addr_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->ip_src.s_addr), src_addr_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_header->ip_dst.s_addr), dst_addr_str, INET_ADDRSTRLEN);
  src_ip_str = std::string(src_addr_str);
  dst_ip_str = std::string(dst_addr_str);
  if (ip_header->ip_p == IPPROTO_TCP) {
    transport_protocol = TransportProtocol::TCP;
  } else if (ip_header->ip_p == IPPROTO_UDP) {
    transport_protocol = TransportProtocol::UDP;
  } else {
    transport_protocol = TransportProtocol::UNKNOWN;
  }
}

