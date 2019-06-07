#include "dsa_signature_encoder.h"
#include <stdexcept>


namespace pgp {

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
