#include "capture.h"
#include "libsniff.h"
#include <vector>

struct SniffingOptions {
public:
  std::vector<NetworkProtocol> network_protocols;
  std::vector<TransportProtocol> transport_protocols;

public:
  SniffingOptions(std::vector<NetworkProtocol> network_protocols, std::vector<TransportProtocol> transport_protocols);
};
