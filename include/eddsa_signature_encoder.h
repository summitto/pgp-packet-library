#pragma once

#include <tuple>                    // for tuple
#include "basic_key.h"              // for basic_key
#include "basic_secret_key.h"       // for basic_secret_key
#include "eddsa_public_key.h"       // for eddsa_public_key
#include "eddsa_secret_key.h"       // for eddsa_secret_key
#include "hash_encoder.h"           // for sha256_encoder
#include "multiprecision_integer.h" // for multiprecision_integer
#include "packet_tag.h"             // for packet_tag
#include "secret_key.h"             // for secret_key_traits


namespace pgp {

    /**
     *  An encoder to produce EDDSA signatures
     */
    class eddsa_signature_encoder : public sha256_encoder
    {
        public:
            /**
             *  Create the encoder
             *
             *  @param key        The secret key with which to make the signature
             */
            template <packet_tag key_tag>
            eddsa_signature_encoder(const basic_key<secret_key_traits<key_tag>> &key) noexcept :
                eddsa_key{get<basic_secret_key<eddsa_public_key, eddsa_secret_key>>(key.key())}
            {}

            /**
             *  Make the signature
             *
             *  @return Tuple of the r and s parameters for the EDDSA signature
             */
            std::tuple<multiprecision_integer, multiprecision_integer> finalize() noexcept;

        private:
            /**
             *  The key with which to make the signature
             */
            basic_secret_key<eddsa_public_key, eddsa_secret_key> eddsa_key;
    };

}
