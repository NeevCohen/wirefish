#include "sniffer.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <net/bpf.h>
#include <net/if.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

Sniffer::Sniffer(SnifferOptions options)
    : options(options), last_read_length(0), read_bytes_consumed(0) {
  read_buffer = std::make_unique<char[]>(options.buffer_length);
};

int Sniffer::get_available_bpf_device() {
  u_int max_bpf_devices;
  size_t len = sizeof(max_bpf_devices);
  int fd;

  // TODO: Check return value
  sysctlbyname("debug.bpf_maxdevices", &max_bpf_devices, &len, NULL, 0);

  std::unique_ptr<char[]> bpf_device_name = std::make_unique<char[]>(11);
  for (u_int i = 0; i < max_bpf_devices; ++i) {
    std::snprintf(bpf_device_name.get(), 11, "/dev/bpf%d", i);
    fd = open(bpf_device_name.get(), O_RDONLY);
    if (fd)
      return fd;
  }

  return -1;
}

void Sniffer::attach_bpf() {
  struct ifreq interface_request;
  std::strcpy((char *)&interface_request.ifr_name,
              options.interface_name.c_str());
  int immediate_mode = 1;

  // open bpf device
  if (options.bpf_device == "") {
    bpf_fd = Sniffer::get_available_bpf_device();
  } else {
    bpf_fd = open(options.bpf_device.c_str(), O_RDONLY);
  }

  if (bpf_fd < 0) {
    std::perror("open");
  }

  // set/get buffer length
  if (options.buffer_length) {
    if (ioctl(bpf_fd, BIOCSBLEN, &options.buffer_length) < 0) {
      std::perror("ioctl(BIOCGBLEN)");
    }
  } else {
    if (ioctl(bpf_fd, BIOCGBLEN, &options.buffer_length) < 0) {
      std::perror("ioctl(BIOCGBLEN)");
    }
  }

  if (ioctl(bpf_fd, BIOCSETIF, &interface_request) < 0) {
    std::perror("ioctl(BIOCSETIF)");
  }

  if (ioctl(bpf_fd, BIOCIMMEDIATE, &immediate_mode) < 0) {
    std::perror("ioctl(BIOCIMMEDIATE)");
  }

  if (ioctl(bpf_fd, BIOCPROMISC, nullptr) < 0) {
    std::perror("ioctl(BIOCIMMEDIATE)");
  }
}

Packet Sniffer::read_next_packet() {
  struct bpf_hdr *bpf_header;
  if (read_bytes_consumed >= last_read_length) {
    read_bytes_consumed = 0;
    std::memset(read_buffer.get(), 0, options.buffer_length);
    ssize_t bytes_read = read(bpf_fd, read_buffer.get(), options.buffer_length);
    if (bytes_read < 0) {
      perror("read");
      throw std::runtime_error("Failed to read from bpf device");
    }
    last_read_length = (size_t)bytes_read;
  }

  bpf_header = (struct bpf_hdr *)(read_buffer.get() + read_bytes_consumed);
  Packet packet;
  packet.data = std::make_unique<char[]>(options.buffer_length);
  std::memcpy(packet.data.get(),
              read_buffer.get() + read_bytes_consumed + bpf_header->bh_hdrlen,
              bpf_header->bh_caplen);
  read_bytes_consumed +=
      BPF_WORDALIGN(bpf_header->bh_caplen + bpf_header->bh_hdrlen);
  return packet;
};

EthernetFrame Sniffer::read_next_ethernet_frame() {
  Packet packet = read_next_packet();
  ether_header_t *ethernet_header = (ether_header_t *)packet.data.get();
  char *network_layer_data = packet.data.get() + sizeof(ether_header_t);
  return EthernetFrame{.header = ethernet_header, .data = network_layer_data};
}

IPPacket Sniffer::read_next_ip_packet() {
	EthernetFrame frame;
	struct ip *ip_header;
	do {
		frame = read_next_ethernet_frame();
		ip_header = (struct ip *)frame.data;
	} while (ip_header->ip_v != 4);
	
  char *transport_layer_data = frame.data + ip_header->ip_hl;
	return IPPacket{.header = ip_header, .data = transport_layer_data};
}

Sniffer::~Sniffer() {
  if (bpf_fd > 0) {
    close(bpf_fd);
  }
}
