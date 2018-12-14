cmake_minimum_required(VERSION 2.8.2)
project(rfc4480)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/GSL/include")

add_executable(dump main.cpp decoder.cpp encoder.cpp packet.cpp public_key.cpp multiprecision_integer.cpp)
set_property(TARGET dump PROPERTY CXX_STANDARD 17)
