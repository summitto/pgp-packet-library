#pragma once

#include "basic_key.h"
#include "rsa_public_key.h"
#include "dsa_public_key.h"
#include "elgamal_public_key.h"
#include "ecdh_public_key.h"
#include "eddsa_public_key.h"
#include "ecdsa_public_key.h"


namespace pgp {

    /**
     *  Trait used for public keys
     */
    template <packet_tag key_tag>
    struct public_key_traits
    {
        using rsa_key_t     = rsa_public_key;
        using elgamal_key_t = elgamal_public_key;
        using dsa_key_t     = dsa_public_key;
        using ecdh_key_t    = ecdh_public_key;
        using eddsa_key_t   = eddsa_public_key;
        using ecdsa_key_t   = ecdsa_public_key;

        /**
         *  Packet tag for public keys
         */
        static constexpr packet_tag tag() noexcept
        {
            return key_tag;
        }

        static constexpr bool is_subkey() noexcept
        {
            return key_tag == packet_tag::public_subkey;
        }
    };

    // specialize the public key type
    using public_key = basic_key<public_key_traits<packet_tag::public_key>>;
    using public_subkey = basic_key<public_key_traits<packet_tag::public_subkey>>;
}
