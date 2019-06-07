#pragma once

#include "secret_key.h"
#include <stdexcept>
#include <gsl/span>


namespace pgp {

    /**
     *  An explicitly unimplemented (i.e. throwing) encoder for unknown signatures
     */
    class unknown_signature_encoder
    {
        public:
            /**
             *  Create a nonexistent encoder; throws.
             */
            unknown_signature_encoder(secret_key);

            /**
             *  Push a value to a nonexistent encoder; throws.
             */
            template <typename T>
            void push(T)
            {
                throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
            }

            /**
             *  Insert a blob to a nonexistent encoder; throws.
             */
            template <typename T>
            unknown_signature_encoder &insert_blob(gsl::span<const T>)
            {
                throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
            }

            /**
             *  Get the hash prefix of a nonexistent encoder; throws.
             */
            std::array<uint8_t, 2> hash_prefix();

            /**
             *  Get the finalized parameters of a nonexistent encoder; throws.
             */
            std::tuple<> finalize();
    };
}
