
cmake_minimum_required(VERSION 3.16)

project(wirefish-cli VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
FILE(GLOB CXX_SOURCES *.cpp)
target_include_directories(lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
add_executable(wirefish-cli ${CXX_SOURCES})