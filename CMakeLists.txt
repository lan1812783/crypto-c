cmake_minimum_required(VERSION 3.16.3)

project(crypto)

set(CMAKE_DEBUG_POSTFIX d)

#######################
### gRPC & Protobuf ###
#######################

# Assumes that gRPC was built using '-DgRPC_SSL_PROVIDER=package'
# E.g. cmake \
#     -DgRPC_INSTALL=ON
#     -DgRPC_BUILD_TESTS=OFF
#     -DCMAKE_INSTALL_PREFIX=/home/lan/.local
#     -DgRPC_SSL_PROVIDER=package
#     ../..

# Assumes that gRPC and all its dependencies are already installed
# on this system, so they can be located by find_package().

# Find Protobuf installation
# Looks for protobuf-config.cmake file installed by Protobuf's cmake installation.
find_package(Protobuf CONFIG REQUIRED)
message(STATUS "Using protobuf ${Protobuf_VERSION}")

set(_PROTOBUF_LIBPROTOBUF protobuf::libprotobuf)
set(_REFLECTION gRPC::grpc++_reflection)
find_program(_PROTOBUF_PROTOC protoc)

# Find gRPC installation
# Looks for gRPCConfig.cmake file installed by gRPC's cmake installation.
find_package(gRPC CONFIG REQUIRED)
message(STATUS "Using gRPC ${gRPC_VERSION}")

set(_GRPC_GRPCPP gRPC::grpc++)
find_program(_GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)

# Proto file
get_filename_component(crypto_proto "protos/crypto.proto" ABSOLUTE)
# Generated sources
add_library(crypto_grpc_proto ${crypto_proto})
protobuf_generate (
    TARGET crypto_grpc_proto
)
protobuf_generate (
    TARGET crypto_grpc_proto
    LANGUAGE grpc
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    PLUGIN protoc-gen-grpc=${_GRPC_CPP_PLUGIN_EXECUTABLE}
)
target_link_libraries(crypto_grpc_proto
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

###################
### Crypto core ###
###################

add_library(crypto_core dh.c)

#######################
### Client & server ###
#######################

foreach(_target crypto_client crypto_server)
    add_executable(${_target} ${_target}.cpp util.c)
    target_link_libraries(${_target}
        crypto_core
        crypto_grpc_proto
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF}) # need not to link OpenSSL because the gRPC static library already has one embeded inside
endforeach()

#############
### Debug ###
#############

foreach (_target crypto_core crypto_client crypto_server)
    set_target_properties(${_target}
        PROPERTIES
        DEBUG_POSTFIX
        ${CMAKE_DEBUG_POSTFIX})
endforeach()

########################
### Demo without rpc ###
########################

# add_executable(main main.c util.c)
# set_target_properties(main PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})
# target_link_libraries(main crypto_core crypto)
