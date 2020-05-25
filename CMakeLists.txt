cmake_minimum_required(VERSION 3.13.0)

project(pgp-packet-library
    VERSION     0.1.1
    LANGUAGES   CXX
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(Boost              REQUIRED)
find_package(sodium     1.0.16  REQUIRED)

# first try to find CryptoPP built using CMake
find_package(cryptopp CONFIG)

# if this didn't work, use our built-in search tool
if (NOT TARGET cryptopp-static)
    find_package(CryptoPP REQUIRED)
endif()

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

include(CheckCXX17SourceRuns)

check_cxx17_source_runs(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/tests/std_variant_test.cpp
    HAVE_STD_VARIANT)

add_library(pgp-packet ${pgp-packet-sources})

if((NOT HAVE_STD_VARIANT) 
    OR (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" 
        AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.3)
    OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" 
        AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8)
    OR (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang"
        AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10.0.1))
    message("No working std::variant found, using mpark::variant")
    set(NEED_MPARK 1)
    target_compile_definitions(pgp-packet PUBLIC USE_MPARK_VARIANT)
endif()

target_link_libraries(pgp-packet PUBLIC Boost::boost)

# do we have a CryptoPP target from a CMake build
if (TARGET cryptopp-static)
    target_link_libraries(pgp-packet PUBLIC cryptopp-static)
else ()
    target_link_libraries(pgp-packet PUBLIC CryptoPP::CryptoPP)
endif()

target_include_directories(pgp-packet PUBLIC ${SODIUM_INCLUDE_DIRS})
target_link_libraries(pgp-packet PUBLIC ${SODIUM_LIBRARIES})

target_include_directories(pgp-packet PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

target_include_directories(pgp-packet PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/GSL/include>
    $<INSTALL_INTERFACE:include/pgp-packet/GSL/include>
)

if(NEED_MPARK)
    target_include_directories(pgp-packet PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/variant/include>
        $<INSTALL_INTERFACE:include/pgp-packet/variant/include>
    )
endif()

set_property(TARGET pgp-packet PROPERTY CXX_STANDARD 17)
target_compile_features(pgp-packet PUBLIC cxx_std_17)

# TODO: Figure out correct flags for other compilers
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(pgp-packet PRIVATE -Wall -Wextra -Wdeprecated -Wdocumentation -Wno-sign-compare)
elseif(CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(pgp-packet PRIVATE -Wall -Wextra -Wdeprecated -Wno-sign-compare)
else()
    message(WARNING "Unsupported compiler: don't know what compiler flags to add for this compiler!")
endif()

# allow the user to enable some clang sanitizers
option(ASAN "Enable the address sanitizer (clang only)" OFF)
option(MSAN "Enable the memory sanitizer (clang only)" OFF)

# function to enable a particular clang sanitizer
function(enable_clang_sanitizer sanitizer)
    # does the user want to use the address sanitizer
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        # enable the address sanitizer during build- and link step
        target_compile_options(pgp-packet PUBLIC -fsanitize=${sanitizer})
        target_compile_options(pgp-packet PUBLIC -fno-omit-frame-pointer)
        target_compile_options(pgp-packet PUBLIC -fno-optimize-sibling-calls)
        target_link_options(pgp-packet PUBLIC -fsanitize=${sanitizer})
    else()
        # unable to enable the option for this compiler
        message(WARNING "Unable to enable ${sanitizer} sanitizer, compiler ${CMAKE_CXX_COMPILER_ID} not supported")
    endif()
endfunction()

# we cannot enable both sanitizers at the same time
if (ASAN AND MSAN)
    # notify the user this is impossible
    message(FATAL_ERROR "Address Sanitizer and Memory Sanitizer cannot be used simultaneously")
elseif(ASAN)
    # enable address sanitizer
    enable_clang_sanitizer(address)
elseif(MSAN)
    #enable memory sanitizer
    enable_clang_sanitizer(memory)
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

install(DIRECTORY GSL DESTINATION include/pgp-packet)

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

find_package(PythonInterp)
find_program(iwyu_tool_path NAMES iwyu_tool.py iwyu_tool)
if (iwyu_tool_path AND PYTHONINTERP_FOUND)
    add_custom_target(iwyu
        COMMAND "${PYTHON_EXECUTABLE}" "${iwyu_tool_path}" -p "${CMAKE_BINARY_DIR}" --
        COMMENT "Running include-what-you-use tool"
        VERBATIM
    )
endif()

find_program(clang_tidy_path NAMES clang-tidy)
if (clang_tidy_path)
    set(pgp-packet-includes
        include/*.h
        include/signature_subpacket/*.h
        include/util/*.h
    )
    #   Additional configuration options (e.g. the enabled checkers) will be
    #   taken from the .clang-tidy file in the root of the repository
    add_custom_target(tidy
        COMMAND ${clang_tidy_path} -p="${CMAKE_CURRENT_BINARY_DIR}" ${pgp-packet-sources} ${pgp-packet-includes}
        COMMENT "Running clang-tidy"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()


find_program(cppcheck_path NAMES cppcheck)
if (cppcheck_path)
    add_custom_target(cppcheck
        COMMAND "${cppcheck_path}"
        "--project=${CMAKE_BINARY_DIR}/compile_commands.json"
        "--quiet"
        "--error-exitcode=1"
        "--enable=warning,portability,unusedFunction,performance"
        "--suppressions-list=${CMAKE_SOURCE_DIR}/CppCheckSuppressions.txt"
        "-rp=${CMAKE_SOURCE_DIR}"
        COMMENT "Running cppcheck"
    )
endif()
