#pragma once

#include "decoder_traits.h"


namespace pgp {

    /**
     *  Templated class to expect a specific number
     *  in the encoded PGP data stream.
     */
    template <typename T, T number>
    class expected_number
    {
        public:
            /**
             *  Constructor
             */
            constexpr expected_number() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::range_error, std::out_of_range
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            expected_number(decoder &parser)
            {
                // check whether the value is as expected
                if (parser.template extract_number<T>() != number) {
                    // invalid number was read
                    throw std::range_error{ "A fixed number is outside of expected range" };
                }
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             *  @throws std::runtime_error
             */
            constexpr static size_t size()
            {
                // this is just the size of the number type
                return sizeof(T);
            }

            /**
             *  The value of the number
             *  @return The expected number
             */
            constexpr T value() const noexcept
            {
                // return the expected value
                return number;
            }

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // write out the number
                writer.push(value());
            }
    };

}
