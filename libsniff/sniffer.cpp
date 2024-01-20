#include "sniffer.h"

#include <exception>
#include <iostream>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


Sniffer::Sniffer(SnifferOptions options) : options(options){
	packet_buffer = std::make_unique<char[]>(options.buffer_length);
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
	std::memset(packet_buffer.get(), 0, options.buffer_length);
	if (read(bpf_fd, packet_buffer.get(), options.buffer_length) < 0) {
		perror("read");
		// TODO: Throw exception?
		throw std::exception();
	}
	struct bpf_hdr *bpf_header = (struct bpf_hdr *)packet_buffer.get();
	Packet packet = {.data = nullptr};
	packet.data = std::make_unique<char[]>(options.buffer_length);
	std::memcpy(packet.data.get(), packet_buffer.get() + bpf_header->bh_hdrlen, options.buffer_length - bpf_header->bh_hdrlen);
	return packet;
}

ether_header_t Sniffer::read_next_ethernet_frame() {
	return ether_header_t {0};
}

Sniffer::~Sniffer() {
  if (bpf_fd > 0) {
    close(bpf_fd);
  }
}
