#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <thread>
#include <unistd.h>

#include "capture.h"
#include "libsniff.h"
#include "arg_parse.h"
#include "sniffing_options.h"

void print_tcp(const TCPFrame &tcp);
void print_udp(const UDPDatagram &udp);
void print_arp(const ARPPacket &arp);

int main(int argc, char **argv)
{
  if (getuid())
  {
    std::cerr << "Please run as root user\n";
    return EXIT_FAILURE;
  }

  SniffingOptions sniffing_options;
  try
  {
    sniffing_options = parse_args(argc, argv);
  }
  catch (std::invalid_argument &e)
  {
    std::cerr << "ERROR: \n\t";
    std::cerr << e.what() << "\n";
    return EXIT_FAILURE;
  }

  try
  {
    SnifferOptions opts{.interface_name = sniffing_options.interface_name};
    std::atomic_bool stop{true};
    Sniffer sniffer(opts);
    sniffer.attach_bpf();

    int i = 0;
    if (sniffing_options.packet_count == 0)
    {
      i = -1;
    }

    while (i < sniffing_options.packet_count)
    {
      auto cap = sniffer.read_next_capture(stop);
      if (!cap.has_value())
      {
        continue;
      }
      EthernetFrame ether(cap.value());
      if (ether.network_protocol == NetworkProtocol::UNKNOWN)
      {
        std::cout << "Unknown network protocol - 0x" << std::hex << ntohs(ether.ethernet_header->ether_type) << "\n";
      }
      else if (ether.network_protocol == NetworkProtocol::ARP)
      {
        print_arp(ARPPacket(ether));
      }
      else if (ether.network_protocol == NetworkProtocol::IPv4 || ether.network_protocol == NetworkProtocol::IPv6)
      {
        IPPacket ip(ether);
        if (ip.transport_protocol == TransportProtocol::TCP)
        {
          print_tcp(TCPFrame(ip));
        }
        else if (ip.transport_protocol == TransportProtocol::UDP)
        {
          print_udp(UDPDatagram(ip));
        }
      }
      std::cout << "====================\n";
      if (sniffing_options.packet_count != 0)
      {
        i++;
      }
    }
    return 0;
  }
  catch (const std::runtime_error &e)
  {
    std::cerr << "RUNTIME ERROR: \n\t";
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  catch (...)
  {
    std::cerr << "UNKNOWN ERROR OCCURRED" << std::endl;
    return EXIT_FAILURE;
  }
}

void print_tcp(const TCPFrame &tcp)
{
  std::printf("%s:%hu -> %s:%hu (TCP)\n", tcp.ip.src_ip_str.c_str(),
              tcp.source_port,
              tcp.ip.dst_ip_str.c_str(),
              tcp.dest_port);
}

void print_udp(const UDPDatagram &udp)
{
  std::printf("%s:%hu -> %s:%hu (UDP)\n", udp.ip.src_ip_str.c_str(),
              udp.source_port,
              udp.ip.dst_ip_str.c_str(),
              udp.dest_port);
}

void print_arp(const ARPPacket &arp)
{
  if (arp.operation == ArpOperation::Request)
  {
    std::cout << "Who has " << parse_ip_address(arp.target_protocol_address) << "? Tell " << parse_ip_address(arp.sender_protocol_address) << " (ARP Request)" << std::endl;
  }
  else if (arp.operation == ArpOperation::Reply)
  {
    std::cout << parse_ip_address(arp.sender_protocol_address) << " is at " << parse_mac_address(arp.sender_hardware_address) << " (ARP Reply)" << std::endl;
  }
  else
  {
    std::cout << "Unsupported ARP operation";
  }
}
