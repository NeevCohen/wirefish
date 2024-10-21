cmake_minimum_required(VERSION 3.16)

project(wirefish VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(lib)
add_subdirectory(cli)
add_subdirectory(app)
target_link_libraries(cli PRIVATE lib)
target_link_libraries(app PRIVATE lib)