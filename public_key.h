#pragma once

#include "basic_key.h"
#include "rsa_public_key.h"
#include "dsa_public_key.h"
#include "elgamal_public_key.h"
#include "eddsa_public_key.h"


namespace pgp {

    /**
     *  Trait used for public keys
     */
    struct public_key_traits
    {
        using rsa_key_t     = rsa_public_key;
        using elgamal_key_t = elgamal_public_key;
        using dsa_key_t     = dsa_public_key;
        using eddsa_key_t   = eddsa_public_key;

        /**
         *  Packet tag for public keys
         */
        static constexpr packet_tag tag() noexcept
        {
            return packet_tag::public_key;
        }
    };

    // specialize the public key type
    using public_key = basic_key<public_key_traits>;
}
