#include "ethernet_frame.h"
#include "capture.h"


EthernetFrame::EthernetFrame(Capture& capture): capture(capture) {
  ethernet_header = (ether_header_t *)capture.buffer.data();
  ethernet_data = (char*)ethernet_header + sizeof(ether_header_t);
  u_short ether_type = ntohs(ethernet_header->ether_type);
  if (ether_type == ETHERTYPE_IP) {
    network_protocol = NetworkProtocol::IPv4;
  } else if (ether_type == ETHERTYPE_ARP) {
    network_protocol = NetworkProtocol::ARP;
  } else if (ether_type == ETHERTYPE_IPV6) {
    network_protocol = NetworkProtocol::IPv6;
  } else {
    network_protocol = NetworkProtocol::UNKNOWN;
  }
}

