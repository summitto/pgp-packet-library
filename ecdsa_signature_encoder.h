#pragma once

#include "multiprecision_integer.h"
#include "gcrypt_encoder.h"
#include "secret_key.h"
#include <tuple>


namespace pgp {

    /**
     *  An encoder to produce ECDSA signatures
     */
    class ecdsa_signature_encoder : public gcrypt_encoder<gcrypt_sha256_encoding>
    {
        public:
            /**
             *  Create the encoder
             *
             *  @param key        The secret key with which to make the signature
             */
            ecdsa_signature_encoder(secret_key key) noexcept;

            /**
             *  Make the signature
             *
             *  @return Tuple of the r and s parameters for the ECDSA signature
             */
            std::tuple<multiprecision_integer, multiprecision_integer> finalize();

        private:
            /**
             *  The key with which to make the signature
             */
            secret_key key;
    };

}