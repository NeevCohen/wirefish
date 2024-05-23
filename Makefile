.PHONY := all mkdir wirefish lib clean

MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PROJ_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))

CXX := clang++
CXXFLAGS := -std=c++17 -Wall -Wextra -pedantic -g
CXXFLAGS_DYLIB := $(CXXFLAGS) -shared
LIBSNIFF_DIR := $(PROJ_DIR)/libsniff
LIBSNIFF_SOURCES := $(LIBSNIFF_DIR)/sniffer.cpp $(LIBSNIFF_DIR)/capture.cpp $(LIBSNIFF_DIR)/ethernet_frame.cpp $(LIBSNIFF_DIR)/ip_packet.cpp $(LIBSNIFF_DIR)/tcp_frame.cpp $(LIBSNIFF_DIR)/udp_datagram.cpp
LIBSNIFF_HEADERS := $(LIBSNIFF_DIR)/libsniff.h $(LIBSNIFF_DIR)/sniffer.h $(LIBSNIFF_DIR)/capture.h $(LIBSNIFF_DIR)/ethernet_frame.h $(LIBSNIFF_DIR)/ip_packet.h $(LIBSNIFF_DIR)/tcp_frame.h $(LIBSNIFF_DIR)/udp_datagram.h
CLI_DIR := $(PROJ_DIR)/cli
CLI_SOURCES := $(CLI_DIR)/main.cpp
BUILD_DIR := $(PROJ_DIR)/build

all: mkdir lib wirefish

mkdir:
	mkdir -p $(BUILD_DIR)

wirefish: lib $(CLI_SOURCES)
	$(CXX) $(CXXFLAGS) $(CLI_SOURCES) -I$(LIBSNIFF_DIR) -L$(BUILD_DIR) -lsniff -o $(BUILD_DIR)/wirefish

lib: $(LIBSNIFF_SOURCES) $(LIBSNIFF_HEADERS)
	$(CXX) $(CXXFLAGS_DYLIB) $(LIBSNIFF_SOURCES) -o $(BUILD_DIR)/libsniff.dylib

clean:
	rm -r build/
