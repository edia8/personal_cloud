cmake_minimum_required(VERSION 3.16)
# Project Name
project(MyQtApp LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON) 
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
find_package(Qt6 REQUIRED COMPONENTS Widgets Sql) 
find_package(OpenSSL REQUIRED)

add_executable(MyQtApp 
    CLIENT/main.cpp 
    CLIENT/UI/mainwindow.cpp 
    CLIENT/UI/mainwindow.hpp 
    CLIENT/UI/mainwindow.ui
    CLIENT/client.cpp
    CLIENT/client.hpp
    CLIENT/UI/fileexplorerwindow.cpp
    CLIENT/UI/fileexplorerwindow.hpp
    CLIENT/UI/fileexplorerwindow.ui
)
target_include_directories(MyQtApp PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/PROTOCOL
    ${CMAKE_CURRENT_SOURCE_DIR}/CLIENT
    ${CMAKE_CURRENT_SOURCE_DIR}/CLIENT/UI
)

target_link_libraries(MyQtApp PRIVATE Qt6::Widgets Qt6::Sql OpenSSL::SSL OpenSSL::Crypto)

