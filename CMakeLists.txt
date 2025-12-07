cmake_minimum_required(VERSION 3.16)
# Project Name
project(MyQtApp LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON) 
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
find_package(Qt6 REQUIRED COMPONENTS Widgets Sql) 
add_executable(MyQtApp 
    main.cpp 
    mainwindow.cpp 
    mainwindow.hpp 
    mainwindow.ui
    client.cpp
    client.hpp
    fileexplorerwindow.cpp
    fileexplorerwindow.hpp
    fileexplorerwindow.ui
)
target_link_libraries(MyQtApp PRIVATE Qt6::Widgets Qt6::Sql)

