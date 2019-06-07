#pragma once

#include "multiprecision_integer.h"
#include "hash_encoder.h"
#include "secret_key.h"
#include <tuple>


namespace pgp {

    /**
     *  An encoder to produce DSA signatures
     */
    class dsa_signature_encoder : public sha256_encoder
    {
        public:
            /**
             *  Create the encoder
             *
             *  @param key        The secret key with which to make the signature
             */
            dsa_signature_encoder(secret_key key);

            /**
             *  Make the signature
             *
             *  @return Tuple of the r and s parameters for the DSA signature
             */
            std::tuple<multiprecision_integer, multiprecision_integer> finalize();
    };

}
