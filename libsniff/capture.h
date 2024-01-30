#include <memory>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#pragma once

struct Capture {
protected:
	std::unique_ptr<char[]> internal_buffer;

public:
	const char *data;
	size_t buffer_size;

public:
	Capture(std::unique_ptr<char[]> buffer, size_t buffer_size);
	Capture(size_t buffer_size);
	Capture(Capture &&other);
	~Capture();
};

struct EthernetFrame: public Capture {
public:
	const ether_header_t *const ethernet_header;
	const char *const ethernet_data;
	EthernetFrame(std::unique_ptr<char[]> buffer, size_t buffer_size);
	EthernetFrame(size_t buffer_size);
	EthernetFrame(Capture &capture);
	EthernetFrame(EthernetFrame &&other);
};

struct IPPacket: public EthernetFrame {
public:
	struct ip *ip_header;
	char *ip_data;
	IPPacket(std::unique_ptr<char[]> buffer, size_t buffer_size);
	IPPacket(size_t buffer_size);
	IPPacket(EthernetFrame &frame);
	IPPacket(IPPacket &&other);
};

