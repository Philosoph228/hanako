cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(hanako LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL3 REQUIRED libnl-3.0 libnl-route-3.0)
pkg_check_modules(LIBMNL REQUIRED libmnl)
pkg_check_modules(LIBNFTNL REQUIRED libnftnl)

add_executable(${PROJECT_NAME} main.cpp)

target_include_directories(${PROJECT_NAME}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/dist/boost_1_88_0/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/dist/openssl-1.1.1w/include
    ${LIBNL3_INCLUDE_DIRS}
    ${LIBMNL_INCLUDE_DIRS}
    ${LIBNFTNL_INCLUDE_DIRS}
    
)

target_link_directories(${PROJECT_NAME}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/dist/boost_1_88_0/lib
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/dist/openssl-1.1.1w/lib
    
)

target_link_libraries(${PROJECT_NAME} PRIVATE ssl crypto ${LIBNL3_LIBRARIES} ${LIBMNL_LIBRARIES} ${LIBNFTNL_LIBRARIES})

