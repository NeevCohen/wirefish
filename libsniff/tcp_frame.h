#include <netinet/tcp.h>

#include "ip_packet.h"

#pragma once

struct TCPFrame {
public:
  const IPPacket ip;
  const struct tcphdr *tcp_header;
  u_short tcp_sport;
  u_short tcp_dport;
  const char *tcp_payload;

public:
  TCPFrame(IPPacket& ip);
};
