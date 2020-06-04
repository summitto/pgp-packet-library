cmake_minimum_required(VERSION 3.13.0)

project(pgp-packet-examples
        VERSION 0.0.1
        LANGUAGES CXX)

find_package(pgp-packet REQUIRED)

add_executable(create_simple_packet create_simple_packet.cpp)
target_link_libraries(create_simple_packet pgp-packet)

add_executable(encoding_and_decoding encoding_and_decoding.cpp)
target_link_libraries(encoding_and_decoding pgp-packet)

add_executable(key_from_raw_data key_from_raw_data.cpp)
target_link_libraries(key_from_raw_data pgp-packet)
