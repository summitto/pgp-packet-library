#pragma once

#include "basic_key.h"
#include "basic_secret_key.h"
#include "rsa_secret_key.h"
#include "rsa_public_key.h"
#include "dsa_secret_key.h"
#include "dsa_public_key.h"
#include "elgamal_secret_key.h"
#include "ecdh_secret_key.h"
#include "ecdh_public_key.h"
#include "eddsa_secret_key.h"
#include "eddsa_public_key.h"
#include "ecdsa_secret_key.h"


namespace pgp {

    /**
     *  Trait used for secret keys
     */
    template <packet_tag key_tag>
    struct secret_key_traits
    {
        using rsa_key_t     = basic_secret_key<rsa_public_key, rsa_secret_key>;
        using elgamal_key_t = basic_secret_key<elgamal_public_key, elgamal_secret_key>;
        using dsa_key_t     = basic_secret_key<dsa_public_key, dsa_secret_key>;
        using ecdh_key_t    = basic_secret_key<ecdh_public_key, ecdh_secret_key>;
        using eddsa_key_t   = basic_secret_key<eddsa_public_key, eddsa_secret_key>;
        using ecdsa_key_t   = basic_secret_key<ecdsa_public_key, ecdsa_secret_key>;

        /**
         *  Packet tag for secret keys
         */
        static constexpr packet_tag tag() noexcept
        {
            return key_tag;
        }

        static constexpr bool is_subkey() noexcept
        {
            return key_tag == packet_tag::secret_subkey;
        }
    };

    // specialize the secret key types
    using secret_key = basic_key<secret_key_traits<packet_tag::secret_key>>;
    using secret_subkey = basic_key<secret_key_traits<packet_tag::secret_subkey>>;
}
