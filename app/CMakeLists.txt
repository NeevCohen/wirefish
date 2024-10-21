cmake_minimum_required(VERSION 3.16)

project(app VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_PREFIX_PATH "/opt/qt5-build/")

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_add_executable(app
    main.cpp
)

target_link_libraries(app PRIVATE Qt::Widgets)

set_target_properties(app PROPERTIES
    MACOSX_BUNDLE ON
)