#include <memory>
#include <string>
#include <mutex>

#include "capture.h"

#pragma once

struct SnifferOptions {
	std::string bpf_device;
	std::string interface_name;
	u_int buffer_length;
};

struct Sniffer {

private:
	SnifferOptions options;
	int bpf_fd;
	std::unique_ptr<char[]> read_buffer;
	size_t last_read_length;
	size_t read_bytes_consumed;
	std::mutex read_lock;

private:
	static int get_available_bpf_device();
	void fill_buffer();

public:
	Sniffer(SnifferOptions options);
	Capture read_next_capture();
	EthernetFrame read_next_ethernet_frame();
	IPPacket read_next_ip_packet();
	TCPFrame read_next_tcp_frame();
	UDPDatagram read_next_udp_datagram();
	void attach_bpf();
	~Sniffer();
};


