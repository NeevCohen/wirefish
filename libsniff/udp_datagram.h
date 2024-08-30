#include "ip_packet.h"

#pragma once

struct UDPDatagram {
public:
  const IPPacket& ip;
  u_short source_port;
  u_short dest_port;
  u_short length;
  const char *udp_payload;

public:
  UDPDatagram(IPPacket& ip);
};
