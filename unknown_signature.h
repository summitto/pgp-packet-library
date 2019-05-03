#pragma once

#include "secret_key.h"
#include <stdexcept>
#include "decoder.h"


namespace pgp {

    /**
     *  Class for holding an unknown signature
     */
    class unknown_signature
    {
        public:
            struct encoder_t
            {
                encoder_t(secret_key)
                {
                    throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
                }

                template <typename T>
                void push(T)
                {
                    throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
                }

                template <typename T>
                encoder_t &insert_blob(gsl::span<const T>)
                {
                    throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
                }

                std::array<uint8_t, 2> hash_prefix()
                {
                    throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
                }

                std::tuple<> finalize()
                {
                    throw std::runtime_error{ "Unknown signatures cannot sign streamed data" };
                }
            };

            /**
             *  Constructor
             */
            unknown_signature() = default;
            /**
             *  Constructor
             */
            unknown_signature(decoder&) noexcept {}

            /**
             *  Comparison operators
             */
            bool operator==(const unknown_signature&) const noexcept
            {
                return true;
            }

            /**
             *  Comparison operators
             */
            bool operator!=(const unknown_signature &other) const noexcept
            {
                return !operator==(other);
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const
            {
                // we do not know the size
                throw std::runtime_error{ "Unknown signatures have an unknown size" };
            }

            /**
             *  Write the data to an encoder
             *
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t&) const
            {
                // unknown key cannot be encoded
                throw std::runtime_error{ "Failed to encode unknown signature" };
            }
    };

}
