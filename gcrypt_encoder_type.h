#pragma once

#include <gcrypt.h>


namespace pgp {

    /**
     *  Structure for describing a digest algorithm
     */
    template <int gcrypt_algorithm, size_t gcrypt_digest_size>
    struct gcrypt_encoder_type
    {
        constexpr static const int algorithm    = gcrypt_algorithm;
        constexpr static const int digest_size  = gcrypt_digest_size;
    };

    /**
     *  Define the used algorithms
     */
    using gcrypt_sha1_encoding      = gcrypt_encoder_type<GCRY_MD_SHA1,     20>;
    using gcrypt_sha256_encoding    = gcrypt_encoder_type<GCRY_MD_SHA256,   32>;

}
