#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <vector>

#include "arg_parse.h"
#include "capture.h"

std::vector<NetworkProtocol> parse_network_protocols(const char *args);
std::vector<TransportProtocol> parse_transport_protocols(const char *args);

SniffingOptions parse_args(int argc, char *const *argv) {
  std::vector<NetworkProtocol> network_protos;
  std::vector<TransportProtocol> transport_protos;

  int c;

  while ((c = getopt(argc, argv, "n:t:")) != -1) {
    switch (c) {
      case 'n':
        network_protos = parse_network_protocols(optarg);
      case 't':
        transport_protos = parse_transport_protocols(optarg);
      case '?':
        if (optopt == 'n' || optopt == 't') {
          throw std::invalid_argument(std::string("Option -") + char(optopt) + " requires an argument");
        }
        else if (isprint (optopt)) {
          throw std::invalid_argument(std::string("Unknown option -") + char(optopt));
        }
        else {
          throw std::invalid_argument(std::string("Unknown option character ") + std::to_string(optopt));
        }
    }
  }

  return SniffingOptions(network_protos, transport_protos);
}

std::vector<NetworkProtocol> parse_network_protocols(const char *arg) {
  std::string arg_str(arg);
  std::vector<NetworkProtocol> network_opts;
  size_t next = 0, last = 0;
  std::string delim = ",";
    

  while ((next = arg_str.find(delim, last)) != std::string::npos)  {
    std::string proto = arg_str.substr(last, next-last); 
    if (proto == "ipv4") {
      network_opts.push_back(NetworkProtocol::IPv4);
    } else if (proto == "ipv6") {
      network_opts.push_back(NetworkProtocol::IPv6);
    } else if (proto == "arp") {
      network_opts.push_back(NetworkProtocol::ARP);
    }
    last = next + 1;
  }

  return network_opts;
}

std::vector<TransportProtocol> parse_transport_protocols(const char *arg) {
  std::string arg_str(arg);
  std::vector<TransportProtocol> transport_protos;
  size_t next = 0, last = 0;
  char delim = ',';
    

  while ((next = arg_str.find(delim, last)) != std::string::npos)  {
    std::string proto = arg_str.substr(last, next-last); 
    if (proto == "tcp") {
      transport_protos.push_back(TransportProtocol::TCP);
    } else if (proto == "udp") {
      transport_protos.push_back(TransportProtocol::UDP);
    }   
    last = next + 1;
  }

  return transport_protos;
}
