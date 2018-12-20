cmake_minimum_required(VERSION 2.8.2)
project(rfc4480)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/GSL/include")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/variant/include")

add_executable(dump
    main.cpp
    decoder.cpp
    encoder.cpp
    packet.cpp
    user_id.cpp
    curve_oid.cpp
    signature.cpp
    rsa_signature.cpp
    dsa_signature.cpp
    rsa_public_key.cpp
    rsa_secret_key.cpp
    dsa_public_key.cpp
    dsa_secret_key.cpp
    variable_number.cpp
    eddsa_signature.cpp
    eddsa_public_key.cpp
    eddsa_secret_key.cpp
    elgamal_public_key.cpp
    elgamal_secret_key.cpp
    signature_subpacket.cpp
    multiprecision_integer.cpp
    signature_subpacket_set.cpp
)

set_property(TARGET dump PROPERTY CXX_STANDARD 17)
