#include "sniffer.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <mutex>
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
  if (sysctlbyname("debug.bpf_maxdevices", &max_bpf_devices, &len, NULL, 0) <
      0) {
    throw std::runtime_error("Failed to get maximum number of bpf devices");
  }

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
    std::printf("uid %d\n", getuid());
    std::perror("open");
    throw std::runtime_error("Failed to open bpf device");
  }

  // set/get buffer length
  if (options.buffer_length) {
    if (ioctl(bpf_fd, BIOCSBLEN, &options.buffer_length) < 0) {
      std::perror("ioctl(BIOCGBLEN)");
      throw std::runtime_error("Failed to set bpf buffer length");
    }
  } else {
    if (ioctl(bpf_fd, BIOCGBLEN, &options.buffer_length) < 0) {
      std::perror("ioctl(BIOCGBLEN)");
      throw std::runtime_error("Failed to get bpf buffer length");
    }
  }

  if (ioctl(bpf_fd, BIOCSETIF, &interface_request) < 0) {
    std::perror("ioctl(BIOCSETIF)");
    throw std::runtime_error("Failed to attatch bpf to interface");
  }

  if (ioctl(bpf_fd, BIOCIMMEDIATE, &immediate_mode) < 0) {
    std::perror("ioctl(BIOCIMMEDIATE)");
    throw std::runtime_error("Failed to enable immediate mode");
  }

  if (ioctl(bpf_fd, BIOCPROMISC, nullptr) < 0) {
    std::perror("ioctl(BIOCPROMISC)");
    throw std::runtime_error("Failed to set interface to promiscuous mode");
  }
}

void Sniffer::fill_buffer(int t) {
  read_bytes_consumed = 0;
  std::memset(read_buffer.get(), 0, options.buffer_length);
  ssize_t bytes_read = read(bpf_fd, read_buffer.get(), options.buffer_length);
	std::printf("%d read %lu\n", t, bytes_read);
  if (bytes_read < 0) {
    perror("read");
    throw std::runtime_error("Failed to read from bpf device");
  }
  last_read_length = (size_t)bytes_read;
}

Capture Sniffer::read_next_capture(int t) {
	std::printf("%d is waiting for lock\n", t);
  std::lock_guard<std::mutex> lock_guard(read_lock);
	std::printf("%d is reading next capture\n", t);
  if (read_bytes_consumed >= last_read_length) {
		std::printf("%d is filling buffer rbc=%lu lrl=%lu\n", t, read_bytes_consumed, last_read_length);
		fill_buffer(t);
  }
  struct bpf_hdr *bpf_header =
      (struct bpf_hdr *)(read_buffer.get() + read_bytes_consumed);
  Capture capture(bpf_header->bh_caplen);
  std::memcpy((void *)capture.data,
              read_buffer.get() + read_bytes_consumed + bpf_header->bh_hdrlen,
              bpf_header->bh_caplen);
  read_bytes_consumed +=
      BPF_WORDALIGN(bpf_header->bh_caplen + bpf_header->bh_hdrlen);
	std::printf("%d read rbc=%lu lrl=%lu\n", t, read_bytes_consumed, last_read_length);
  return capture;
};

EthernetFrame Sniffer::read_next_ethernet_frame(int t) {
  Capture capture = read_next_capture(t);
  EthernetFrame frame(capture);
  return frame;
}

IPPacket Sniffer::read_next_ip_packet(int t) {
  struct ip *ip_header;
  do {
    EthernetFrame frame = read_next_ethernet_frame(t);
    ip_header = (struct ip *)frame.ethernet_data;
    if (ip_header->ip_v == 4) {
      return IPPacket(frame);
    }
  } while (true);
}

Sniffer::~Sniffer() {
	std::cout << "Dtor\n";
  if (bpf_fd > 0) {
    close(bpf_fd);
  }
}
