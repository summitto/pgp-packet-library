FROM debian:buster

RUN apt-get update \
&&  apt-get -y install \
        gnupg \
        software-properties-common \
        wget \
&&  wget --quiet -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
&&  add-apt-repository -y "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-8 main" \
&&  apt-get update \
&&  apt-get -y upgrade \
&&  apt-get -y install \
        build-essential \
        clang-8 \
        clang-tools-8 \
        cmake \
        g++-8 \
        libboost1.67-all-dev \
        libcrypto++-dev \
        libsodium-dev \
&&  apt-get -y autoremove \
&&  apt-get -y autoclean \
&&  ln -s $(which llvm-profdata-8) /usr/bin/llvm-profdata \
&&  ln -s $(which llvm-cov-8) /usr/bin/llvm-cov \
&&  mkdir /pgp-packet-library

WORKDIR /pgp-packet-library

COPY . /pgp-packet-library

