#pragma once

#include <stdexcept>                // for runtime_error
#include <tuple>                    // for tuple
#include "basic_key.h"              // for basic_key
#include "hash_encoder.h"           // for sha256_encoder
#include "multiprecision_integer.h" // for multiprecision_integer
#include "packet_tag.h"             // for packet_tag
#include "secret_key.h"             // for secret_key_traits


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
