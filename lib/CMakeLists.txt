cmake_minimum_required(VERSION 3.16)

project(lib VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
FILE(GLOB CXX_SOURCES *.cpp)
add_library(lib STATIC ${CXX_SOURCES})
target_include_directories(lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})