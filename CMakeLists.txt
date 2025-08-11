cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(hanako LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(${PROJECT_NAME} main.cpp)

target_include_directories(${PROJECT_NAME}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/dist/boost_1_88_0/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/dist/openssl-1.1.1w/include
)

target_link_directories(${PROJECT_NAME}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/dist/boost_1_88_0/lib
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/dist/openssl-1.1.1w/lib
)

target_link_libraries(${PROJECT_NAME} PRIVATE ssl crypto)

