cmake_minimum_required(VERSION 3.16)

project(wirefish VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_PREFIX_PATH "/opt/qt5-build/")

find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

qt_add_executable(wirefish
    main.cpp
)

target_link_libraries(wirefish PRIVATE Qt::Widgets)

set_target_properties(wirefish PROPERTIES
    MACOSX_BUNDLE ON
)