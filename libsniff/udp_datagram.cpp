#include "udp_datagram.h"


UDPDatagram::UDPDatagram(IPPacket& ip): ip(ip){
  u_short* udp_header = (u_short*)ip.ip_data;
  source_port = ntohs(udp_header[0]);
  dest_port = ntohs(udp_header[1]);
  length = ntohs(udp_header[2]);
  udp_payload = ip.ip_data + 8;
}
