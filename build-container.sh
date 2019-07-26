#!/bin/bash

if [[ -z ${PGPPL_BUILDER_IMAGE_NAME} ]]; then
    PGPPL_BUILDER_IMAGE_NAME='summitto/pgp-packet-library-builder'
fi

docker build -t ${PGPPL_BUILDER_IMAGE_NAME} .

