#pragma once

#include "basic_key.h"
#include "rsa_secret_key.h"
#include "dsa_secret_key.h"
#include "elgamal_secret_key.h"
#include "eddsa_secret_key.h"


namespace pgp {

    /**
     *  Trait used for secret keys
     */
    struct secret_key_traits
    {
        using rsa_key_t     = rsa_secret_key;
        using elgamal_key_t = elgamal_secret_key;
        using dsa_key_t     = dsa_secret_key;
        using eddsa_key_t   = eddsa_secret_key;

        /**
         *  Packet tag for secret keys
         */
        static constexpr packet_tag tag() noexcept
        {
            return packet_tag::secret_key;
        }
    };

    // specialize the secret key type
    using secret_key = basic_key<secret_key_traits>;
}