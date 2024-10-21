#include "tcp_frame.h"


TCPFrame::TCPFrame(IPPacket& ip): ip(ip) {
  tcp_header = (struct tcphdr*)ip.ip_data;
  source_port = ntohs(tcp_header->th_sport);
  dest_port = ntohs(tcp_header->th_dport);
  tcp_payload = (char*)tcp_header + tcp_header->th_off;
}

