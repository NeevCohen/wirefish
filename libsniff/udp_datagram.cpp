#include "udp_datagram.h"

UDPDatagram::UDPDatagram(IPPacket& ip): ip(ip){
  u_short* udp_header = (u_short*)ip.ip_data;
  udp_sport = ntohs(udp_header[0]);
  udp_dport = ntohs(udp_header[1]);
  udp_length = ntohs(udp_header[2]);
  udp_payload = ip.ip_data + 8;
}
