#pragma once

#include "multiprecision_integer.h"
#include "hash_encoder.h"
#include "secret_key.h"
#include <tuple>


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
                eddsa_key{mpark::get<basic_secret_key<eddsa_public_key, eddsa_secret_key>>(key.key())}
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
