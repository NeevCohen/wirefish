#include "tcp_frame.h"

TCPFrame::TCPFrame(IPPacket& ip): ip(ip) {
  tcp_header = (struct tcphdr*)ip.ip_data;
  tcp_sport = ntohs(tcp_header->th_sport);
  tcp_dport = ntohs(tcp_header->th_dport);
  tcp_payload = (char*)tcp_header + tcp_header->th_off;
}

