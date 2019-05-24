#include "dsa_signature_encoder.h"
#include <stdexcept>


namespace pgp {

    /**
     *  Create the encoder
     *
     *  @param key        The secret key with which to make the DSA signature
     */
    dsa_signature_encoder::dsa_signature_encoder(secret_key)
    {
        // TODO
        throw std::runtime_error{ "Generating DSA signatures is not yet implemented" };
    }

    /**
     *  Make the signature
     *
     *  @return Tuple of the r and s parameters for the DSA signature
     */
    std::tuple<multiprecision_integer, multiprecision_integer>
    dsa_signature_encoder::finalize()
    {
        // TODO
        throw std::runtime_error{ "Generating DSA signatures is not yet implemented" };
    }

}
