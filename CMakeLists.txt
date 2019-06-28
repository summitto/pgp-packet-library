cmake_minimum_required(VERSION 3.0.2)

project(pgp-packet-library
    VERSION     0.1.1
    LANGUAGES   CXX
)

include(CheckIncludeFileCXX)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(Boost              REQUIRED)
find_package(sodium     1.0.16  REQUIRED)
find_package(CryptoPP           REQUIRED)

set(pgp-packet-sources
    source/decoder.cpp
    source/packet.cpp
    source/user_id.cpp
    source/curve_oid.cpp
    source/signature.cpp
    source/string_to_key.cpp
    source/range_encoder.cpp
    source/rsa_signature.cpp
    source/dsa_signature.cpp
    source/rsa_public_key.cpp
    source/rsa_secret_key.cpp
    source/dsa_public_key.cpp
    source/dsa_secret_key.cpp
    source/variable_number.cpp
    source/ecdh_public_key.cpp
    source/ecdh_secret_key.cpp
    source/eddsa_signature.cpp
    source/eddsa_public_key.cpp
    source/eddsa_secret_key.cpp
    source/ecdsa_signature.cpp
    source/ecdsa_public_key.cpp
    source/ecdsa_secret_key.cpp
    source/elgamal_public_key.cpp
    source/elgamal_secret_key.cpp
    source/multiprecision_integer.cpp
    source/signature_subpacket_set.cpp
    source/rsa_signature_encoder.cpp
    source/dsa_signature_encoder.cpp
    source/ecdsa_signature_encoder.cpp
    source/eddsa_signature_encoder.cpp
    source/unknown_signature_encoder.cpp
    source/signature_subpacket/unknown.cpp
    source/signature_subpacket/issuer_fingerprint.cpp
    source/signature_subpacket/embedded.cpp
)

CHECK_INCLUDE_FILE_CXX(variant HAVE_STD_VARIANT)
CHECK_INCLUDE_FILE_CXX(span HAVE_STD_SPAN)

add_library(pgp-packet ${pgp-packet-sources})

if(NOT HAVE_STD_VARIANT)
    set(NEED_MPARK 1)
    target_compile_definitions(pgp-packet PUBLIC USE_MPARK_VARIANT)
endif()

if(NOT HAVE_STD_SPAN)
    set(NEED_GSL 1)
    target_compile_definitions(pgp-packet PUBLIC USE_GSL_SPAN)
endif()

target_include_directories(pgp-packet PUBLIC ${Boost_INCLUDE_DIRS})

target_include_directories(pgp-packet PUBLIC ${SODIUM_INCLUDE_DIRS})
target_link_libraries(pgp-packet ${SODIUM_LIBRARIES})

target_include_directories(pgp-packet PUBLIC ${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(pgp-packet ${CRYPTOPP_LIBRARIES})

target_include_directories(pgp-packet PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

if(NEED_GSL)
    target_include_directories(pgp-packet PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/GSL/include>
        $<INSTALL_INTERFACE:include/pgp-packet/GSL/include>
    )
endif()

if(NEED_MPARK)
    target_include_directories(pgp-packet PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/variant/include>
        $<INSTALL_INTERFACE:include/pgp-packet/variant/include>
    )
endif()

set_property(TARGET pgp-packet PROPERTY CXX_STANDARD 17)
if(NOT ${CMAKE_VERSION} VERSION_LESS "3.8.0")
    target_compile_features(pgp-packet PUBLIC cxx_std_17)
else()
    message(WARNING "Cannot export requirement for C++17 to users of the pgp-packet library (CMake version < 3.8.0); please set the C++ standard yourself")
endif()

# TODO: Figure out correct flags for other compilers
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(pgp-packet PRIVATE -Wall -Wextra -Wdeprecated -Wdocumentation -Wno-sign-compare)
elseif(CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(pgp-packet PRIVATE -Wall -Wextra -Wdeprecated -Wno-sign-compare)
else()
    message(WARNING "Unsupported compiler: don't know what compiler flags to add for this compiler!")
endif()

add_subdirectory(tests)

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

install(DIRECTORY include/ DESTINATION include/pgp-packet)

if(NEED_GSL)
    install(DIRECTORY GSL DESTINATION include/pgp-packet)
endif()

if(NEED_MPARK)
    install(DIRECTORY variant DESTINATION include/pgp-packet)
endif()

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
