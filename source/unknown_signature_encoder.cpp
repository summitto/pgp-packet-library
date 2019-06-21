#include "unknown_signature_encoder.h"


namespace pgp {


    /**
     *  Get the hash prefix of a nonexistent encoder; throws.
     */
    std::array<uint8_t, 2> unknown_signature_encoder::hash_prefix()
    {
        throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
    }

    /**
     *  Get the finalized parameters of a nonexistent encoder; throws.
     */
    std::tuple<> unknown_signature_encoder::finalize()
    {
        throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
    }

}
