#include "ethernet_frame.h"
#include "capture.h"
#include <sstream>
#include <stdexcept>
#include <string>

EthernetFrame::EthernetFrame(Capture &capture) : capture(capture)
{
  ethernet_header = (ether_header_t *)capture.buffer.data();
  ethernet_data = (char *)ethernet_header + sizeof(ether_header_t);
  uint16_t ether_type = ntohs(ethernet_header->ether_type);
  if (ether_type == ETHERTYPE_IP)
  {
    network_protocol = NetworkProtocol::IPv4;
  }
  else if (ether_type == ETHERTYPE_ARP)
  {
    network_protocol = NetworkProtocol::ARP;
  }
  else if (ether_type == ETHERTYPE_IPV6)
  {
    network_protocol = NetworkProtocol::IPv6;
  }
  else
  {
    network_protocol = NetworkProtocol::UNKNOWN;
  }
}

std::string parse_mac_address(const u_char mac[ETHER_ADDR_LEN])
{
  return parse_mac_address(std::vector<uint8_t>((uint8_t *)mac, (uint8_t *)mac + ETHER_ADDR_LEN));
}

std::string parse_mac_address(const std::vector<uint8_t> &mac)
{
  if (mac.size() < mac_address_length)
  {
    throw std::runtime_error("Invalid MAC address length " + std::to_string(mac.size()));
  }

  std::stringstream stream;
  for (auto i = mac.end(); i != mac.begin(); i--)
  {
    stream << std::hex << (uint16_t)*i;
    if (i - 1 == mac.begin())
    {
      continue;
    }

    stream << ":";
  }

  return stream.str();
}
