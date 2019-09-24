#pragma once

#include <stdexcept>
#include <tuple>
#include "basic_key.h"
#include "hash_encoder.h"
#include "multiprecision_integer.h"
#include "packet_tag.h"
#include "secret_key.h"


namespace pgp {

    /**
     *  An encoder to produce DSA signatures
     */
    class dsa_signature_encoder : public sha256_encoder
    {
        public:
            /**
             *  Create the encoder
             */
            template <packet_tag key_tag>
            dsa_signature_encoder(basic_key<secret_key_traits<key_tag>>)
            {
                // TODO
                throw std::runtime_error{ "Generating DSA signatures is not yet implemented" };
            }

            /**
             *  Make the signature
             *
             *  @return Tuple of the r and s parameters for the DSA signature
             */
            std::tuple<multiprecision_integer, multiprecision_integer> finalize();
    };

}
