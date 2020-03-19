# use EXCLUDE_FROM_ALL to avoid gtest installation
add_subdirectory(googletest EXCLUDE_FROM_ALL)

set(test-sources "")
foreach(source ${pgp-packet-sources})
    list(APPEND test-sources "../${source}")
endforeach(source)

list(APPEND test-sources
    main.cpp
    unit_tests/curve_oid.cpp
    unit_tests/decoder.cpp
    unit_tests/device_random_engine.cpp
    unit_tests/dsa_public_key.cpp
    unit_tests/dsa_secret_key.cpp
    unit_tests/dsa_signature.cpp
    unit_tests/ecdh_public_key.cpp
    unit_tests/ecdh_secret_key.cpp
    unit_tests/ecdsa_public_key.cpp
    unit_tests/ecdsa_secret_key.cpp
    unit_tests/ecdsa_signature.cpp
    unit_tests/eddsa_public_key.cpp
    unit_tests/eddsa_secret_key.cpp
    unit_tests/eddsa_signature.cpp
    unit_tests/elgamal_public_key.cpp
    unit_tests/elgamal_secret_key.cpp
    unit_tests/expected_number.cpp
    unit_tests/fixed_number.cpp
    unit_tests/hash_encoder.cpp
    unit_tests/multiprecision_integer.cpp
    unit_tests/packet.cpp
    unit_tests/public_key.cpp
    unit_tests/range_encoder.cpp
    unit_tests/rsa_public_key.cpp
    unit_tests/rsa_secret_key.cpp
    unit_tests/rsa_signature.cpp
    unit_tests/secret_key.cpp
    unit_tests/signature.cpp
    unit_tests/signature_subpacket_set.cpp
    unit_tests/unknown_signature.cpp
    unit_tests/user_id.cpp
    unit_tests/variable_number.cpp
    unit_tests/signature_subpacket/embedded.cpp
    unit_tests/signature_subpacket/fixed_array.cpp
    unit_tests/signature_subpacket/issuer_fingerprint.cpp
    unit_tests/signature_subpacket/key_flags.cpp
    unit_tests/signature_subpacket/numeric.cpp
    unit_tests/signature_subpacket/unknown.cpp
)

list(APPEND test-sources
    device_random_engine.cpp
    generate.cpp
    key_template.cpp
)

add_executable(tests ${test-sources})
set_property(TARGET tests PROPERTY CXX_STANDARD 17)

# Check which compiler we're using, and set compiler flags and the USE_COVERAGE variable
# TODO: Figure out correct flags for other compilers
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(tests PRIVATE
        -Wall -Wextra -Wdeprecated -Wdocumentation -Wno-sign-compare
        -g -O0 -fprofile-instr-generate -fcoverage-mapping -fsanitize=address)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-instr-generate -fcoverage-mapping -fsanitize=address")
    set(USE_COVERAGE 1)
elseif(CMAKE_COMPILER_IS_GNUCXX)
    message(WARNING "Don't know how to generate coverage information with GCC! The tests will run, but no coverage data can or will be generated.")
    target_compile_options(tests PRIVATE
        -Wall -Wextra -Wdeprecated -Wno-sign-compare
        -g -O0 -fsanitize=address)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    set(USE_COVERAGE 0)
else()
    message(WARNING "Unsupported compiler: don't know what compiler flags to add for this compiler! In particular, no coverage data can or will be generated.")
    set(USE_COVERAGE 0)
endif()

target_include_directories(tests PUBLIC ${LIBGCRYPT_INCLUDE_DIRS})
target_link_libraries(tests ${LIBGCRYPT_LIBRARIES})

target_link_libraries(tests PUBLIC Boost::boost)

# do we have a CryptoPP target from a CMake build
if (TARGET cryptopp-static)
    target_link_libraries(tests PUBLIC cryptopp-static)
else ()
    target_link_libraries(tests PUBLIC CryptoPP::CryptoPP)
endif()

target_include_directories(tests PUBLIC ${SODIUM_INCLUDE_DIRS})
target_link_libraries(tests PUBLIC ${SODIUM_LIBRARIES})

target_include_directories(tests PUBLIC ${PROJECT_SOURCE_DIR}/tests)
target_include_directories(tests PUBLIC ${PROJECT_SOURCE_DIR}/include)
if(NEED_MPARK)
    target_include_directories(tests PUBLIC ${PROJECT_SOURCE_DIR}/variant/include)
    target_compile_definitions(tests PUBLIC USE_MPARK_VARIANT)
endif()
if(NEED_GSL)
    target_include_directories(tests PUBLIC ${PROJECT_SOURCE_DIR}/GSL/include)
    target_compile_definitions(tests PUBLIC USE_GSL_SPAN)
endif()

target_link_libraries(tests PUBLIC gtest_main)

add_custom_target(test
    COMMAND tests
    DEPENDS tests)

if(USE_COVERAGE)
    add_custom_target(profdata
        COMMAND llvm-profdata merge -o ${CMAKE_CURRENT_BINARY_DIR}/default.profdata ${CMAKE_CURRENT_BINARY_DIR}/default.profraw
        DEPENDS test)
else()
    add_custom_target(profdata
        COMMAND echo 'Coverage generation is not supported on your compiler; please use Clang' && false)
endif()

add_custom_target(coverage
    COMMAND llvm-cov report ${CMAKE_CURRENT_BINARY_DIR}/tests -instr-profile=${CMAKE_CURRENT_BINARY_DIR}/default.profdata -ignore-filename-regex='/\(GSL|variant|tests\)/'
    DEPENDS profdata)

add_custom_target(coverage-html
    COMMAND llvm-cov show ${CMAKE_CURRENT_BINARY_DIR}/tests -instr-profile=${CMAKE_CURRENT_BINARY_DIR}/default.profdata -format=html -output-dir=${PROJECT_BINARY_DIR}/coverage -ignore-filename-regex='/\(GSL|variant|tests\)/'
    DEPENDS profdata)
