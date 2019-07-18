#pragma once

#include <cryptopp/integer.h>
#include "decoder_traits.h"
#include "fixed_number.h"
#include "util/span.h"
#include <vector>


namespace pgp {

    /**
     *  A class for working with arbitrary-precision integer numbers
     */
    class multiprecision_integer
    {
        public:
            /**
             *  Constructor
             */
            multiprecision_integer() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::out_of_range
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            multiprecision_integer(decoder &parser) :
                _bits{ parser }
            {
                // first read the number of elements, since it is in bits,
                // we have to round it up to the nearest byte and read it
                size_t count = (_bits + 7) / 8;
        
                // allocate memory for the number
                _data.reserve(count);
        
                // and now read all the elements
                while (_data.size() < count) {
                    // add an element
                    _data.push_back(parser.template extract_number<uint8_t>());
                }
            }

            /**
             *  Constructor
             *
             *  @param  that    The integer to copy or move
             */
            multiprecision_integer(const multiprecision_integer &that) = default;
            multiprecision_integer(multiprecision_integer &&that) = default;

            /**
             *  Constructor
             *
             *  @param  data    The range of numbers
             */
            multiprecision_integer(span<const uint8_t> data) noexcept;

            /**
             *  Constructor
             *
             *  @param  data    The range of numbers
             */
            multiprecision_integer(std::vector<uint8_t> data) noexcept;

            /**
             *  Constructor
             *
             *  @param  integer The Crypto++ integer to convert
             */
            multiprecision_integer(const CryptoPP::Integer &integer) noexcept;

            /**
             *  Assignment
             *
             *  @param  that    The integer to assign
             *  @return Same object for chaining
             */
            multiprecision_integer &operator=(const multiprecision_integer &that) = default;
            multiprecision_integer &operator=(multiprecision_integer &&that) = default;
            multiprecision_integer &operator=(span<const uint8_t> data) noexcept;
            multiprecision_integer &operator=(std::vector<uint8_t> data) noexcept;
            multiprecision_integer &operator=(const CryptoPP::Integer &integer) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const multiprecision_integer &other) const noexcept;
            bool operator!=(const multiprecision_integer &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the data
             *  @return A span containing all the integer numbers
             */
            span<const uint8_t> data() const noexcept;

            /**
             *  Convert to a Crypto++ Integer
             *  @return The Crypto++ Integer that corresponds to the stored value
             */
            explicit operator CryptoPP::Integer() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // write out the number of elements first
                _bits.encode(writer);

                // now write out all the elements
                for (auto number : _data) {
                    // add the number
                    writer.push(number);
                }
            }
        private:
            uint16                  _bits;
            std::vector<uint8_t>    _data;
    };

}
