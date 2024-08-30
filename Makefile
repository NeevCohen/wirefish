.PHONY := all mkdir clean

MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
PROJ_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))

CXX := clang++
CXXFLAGS := -std=c++17 -Wall -Wextra -pedantic -g
CXXFLAGS_DYLIB := $(CXXFLAGS) -shared
LIBSNIFF_SOURCES := $(wildcard libsniff/*.cpp)
LIBSNIFF_HEADERS := $(wildcard libsniff/*.h)
CLI_SOURCES := $(wildcard cli/*.cpp)
CLI_HEADERS := $(wildcard cli/*.h)
BUILD_DIR := $(PROJ_DIR)/build

all: mkdir $(BUILD_DIR)/libsniff.dylib $(BUILD_DIR)/wirefish

mkdir:
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/wirefish: $(BUILD_DIR)/libsniff.dylib $(CLI_SOURCES) $(CLI_HEADERS)
	$(CXX) $(CXXFLAGS) $(CLI_SOURCES) -Icli -Ilibsniff -L$(BUILD_DIR) -lsniff -o $(BUILD_DIR)/wirefish

$(BUILD_DIR)/libsniff.dylib: $(LIBSNIFF_SOURCES) $(LIBSNIFF_HEADERS)
	$(CXX) $(CXXFLAGS_DYLIB) $(LIBSNIFF_SOURCES) -o $(BUILD_DIR)/libsniff.dylib

clean:
	rm -r build/
