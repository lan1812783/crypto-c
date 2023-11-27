cmake_minimum_required(VERSION 3.16.3)

project(app C)

set(CMAKE_DEBUG_POSTFIX d)

add_executable(app main.c dh.c util.c)
set_target_properties(app PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})

target_link_libraries(app crypto)

include_directories(app PUBLIC ${PROJECT_SOURCE_DIR})
