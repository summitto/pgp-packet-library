#!/bin/bash

if [[ -z ${PGPPL_BUILDER_IMAGE_NAME} ]]; then
    PGPPL_BUILDER_IMAGE_NAME='summitto/pgp-packet-library-builder'
fi

if [[ -z ${CXX} ]]; then
    CXX="clang++-8"
fi

compiler_setup="export CXX=${CXX}"
build_dir="build"
build_dir_setup="rm -rf ${build_dir} && mkdir ${build_dir} && cd ${build_dir}"
build_cmd="cmake .. && make -j2"
test_cmd="./tests/tests"

docker run \
    --cap-add SYS_PTRACE \
    ${PGPPL_BUILDER_IMAGE_NAME} \
    /bin/sh \
    -c "${compiler_setup} && ${build_dir_setup} && ${build_cmd} && ${test_cmd}"

