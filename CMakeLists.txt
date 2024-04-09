cmake_minimum_required(VERSION 3.27)
project(group_list_api)

set(CMAKE_CXX_STANDARD 20)

add_executable(group_list_api main.cpp
        Routes.h
        service/DBService.h
        service/base/DBBase.h)


find_package(Crow)
target_link_libraries(group_list_api PUBLIC Crow::Crow)

find_package(PostgreSQL REQUIRED)
target_link_libraries(group_list_api PRIVATE PostgreSQL::PostgreSQL)

add_subdirectory(cpp-jwt)
target_link_libraries(group_list_api PRIVATE cpp-jwt::cpp-jwt)

target_link_libraries(group_list_api PRIVATE -lpqxx -lpq -lssl -lcrypto)

