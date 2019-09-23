#pragma once

#include <cstdint>      // for uint8_t
#include <array>        // for array
#include <stdexcept>    // for runtime_error
#include <tuple>        // for tuple
#include "basic_key.h"  // for basic_key
#include "packet_tag.h" // for packet_tag
#include "secret_key.h" // for secret_key_traits
#include "util/span.h"  // for span


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
            template <packet_tag key_tag>
            unknown_signature_encoder(basic_key<secret_key_traits<key_tag>>)
            {
                throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
            }

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
            unknown_signature_encoder &insert_blob(span<const T>)
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
