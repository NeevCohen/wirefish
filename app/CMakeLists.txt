cmake_minimum_required(VERSION 3.16)

project(wirefish VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_PREFIX_PATH "/opt/qt5-build/")
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
set(CMAKE_AUTOUIC_SEARCH_PATHS wirefish)

qt_add_executable(wirefish
    capture_reader.h
    capture_reader.cpp
    main_window.h
    main_window.cpp
    mainwindow.ui
    main.cpp
)

target_include_directories(wirefish PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(wirefish PRIVATE Qt::Core Qt::Gui Qt::Widgets)

set_target_properties(wirefish PROPERTIES
    MACOSX_BUNDLE ON
)