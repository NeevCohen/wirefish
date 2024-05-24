#include "ip_packet.h"

#pragma once

struct UDPDatagram {
public:
  const IPPacket& ip;
  u_short udp_sport;
  u_short udp_dport;
  u_short udp_length;
  const char *udp_payload;

public:
  UDPDatagram(IPPacket& ip);
};
