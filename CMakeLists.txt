cmake_minimum_required(VERSION 3.0.2)

project(pgp-packet-library
    VERSION     0.1.1
    LANGUAGES   CXX
)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(Boost              REQUIRED)
find_package(LibGcrypt          REQUIRED)
find_package(sodium     1.0.16  REQUIRED)

set(pgp-packet-headers
    array_signature_subpacket.h
    basic_key.h
    dsa_signature.h
    elgamal_public_key.h
    hash_algorithm.h
    hash_encoder.h
    unknown_packet.h
    unknown_signature_subpacket.h
    unknown_signature.h
    basic_secret_key.h
    ecdh_public_key.h
    elgamal_secret_key.h
    gcrypt_encoder.h
    gcrypt_encoder_type.h
    key_algorithm.h
    key_flags_subpacket.h
    range_encoder.h
    rsa_public_key.h
    signature_subpacket_set.h
    user_id.h
    curve_oid.h
    ecdh_secret_key.h
    multiprecision_integer.h
    numeric_signature_subpacket.h
    rsa_secret_key.h
    signature_subpacket_type.h
    variable_number.h
    decoder.h
    eddsa_public_key.h
    packet.h
    range_encoder.h
    rsa_signature.h
    signature_type.h
    dsa_public_key.h
    eddsa_secret_key.h
    expected_number.h
    packet_tag.h
    secret_key.h
    string_to_key.h
    dsa_secret_key.h
    eddsa_signature.h
    fixed_number.h
    public_key.h
    signature.h
    symmetric_key_algorithm.h
    unknown_key.h
)

set(pgp-packet-sources
    decoder.cpp
    packet.cpp
    user_id.cpp
    curve_oid.cpp
    signature.cpp
    string_to_key.cpp
    range_encoder.cpp
    rsa_signature.cpp
    dsa_signature.cpp
    rsa_public_key.cpp
    rsa_secret_key.cpp
    dsa_public_key.cpp
    dsa_secret_key.cpp
    variable_number.cpp
    ecdh_public_key.cpp
    ecdh_secret_key.cpp
    eddsa_signature.cpp
    eddsa_public_key.cpp
    eddsa_secret_key.cpp
    elgamal_public_key.cpp
    elgamal_secret_key.cpp
    multiprecision_integer.cpp
    signature_subpacket_set.cpp
    unknown_signature_subpacket.cpp
)

add_library(pgp-packet ${pgp-packet-sources})

target_include_directories(pgp-packet PUBLIC ${LIBGCRYPT_INCLUDE_DIRS})
target_link_libraries(pgp-packet ${LIBGCRYPT_LIBRARIES})

target_include_directories(pgp-packet PUBLIC ${Boost_INCLUDE_DIRS})

target_include_directories(pgp-packet PUBLIC ${SODIUM_INCLUDE_DIRS})
target_link_libraries(pgp-packet ${SODIUM_LIBRARIES})

target_include_directories(pgp-packet PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/GSL/include>
    $<INSTALL_INTERFACE:include/pgp-packet/GSL/include>
)

target_include_directories(pgp-packet PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/variant/include>
    $<INSTALL_INTERFACE:include/pgp-packet/variant/include>
)

set_property(TARGET pgp-packet PROPERTY CXX_STANDARD 17)

install(
    TARGETS     pgp-packet
    EXPORT      pgp-packet-targets
    DESTINATION lib
)

install(
    EXPORT      pgp-packet-targets
    DESTINATION lib/cmake/pgp-packet
)

install(
    FILES       ${pgp-packet-headers}
    DESTINATION include/pgp-packet
)

install(
    DIRECTORY
        GSL
        util
        variant
    DESTINATION include/pgp-packet
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/pgp-packet/pgp-packet-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

export(
    EXPORT pgp-packet-targets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/pgp-packet/pgp-packet-targets.cmake"
)

configure_file(cmake/pgp-packet-config.cmake
    "${CMAKE_CURRENT_BINARY_DIR}/pgp-packet/pgp-packet-config.cmake"
    COPYONLY
)

install(
    FILES
        cmake/pgp-packet-config.cmake
        "${CMAKE_CURRENT_BINARY_DIR}/pgp-packet/pgp-packet-config-version.cmake"
    DESTINATION
        lib/cmake/pgp-packet
)
