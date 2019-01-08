#pragma once

#include "fixed_number.h"
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
            multiprecision_integer(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  that    The integer to copy or move
             */
            multiprecision_integer(const multiprecision_integer &that) = default;
            multiprecision_integer(multiprecision_integer &&that) = default;

            /**
             *  Assignment
             *
             *  @param  that    The integer to assign
             *  @return Same object for chaining
             */
            multiprecision_integer &operator=(const multiprecision_integer &that) = default;
            multiprecision_integer &operator=(multiprecision_integer &&that) = default;

            /**
             *  Constructor
             *
             *  @param  data    The range of numbers
             */
            multiprecision_integer(gsl::span<const uint8_t> data) noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the data
             *  @return A span containing all the integer numbers
             */
            gsl::span<const uint8_t> data() const noexcept;

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

            /**
             *  Push the key to the hasher
             *
             *  @param  hasher  The hasher to push the value to
             */
            template <class hasher_t>
            void hash(hasher_t &hasher) const noexcept
            {
                // add the size as well as the data
                _bits.hash(hasher);
                hasher.Update(_data.data(), _data.size());
            }
        private:
            uint16                  _bits;
            std::vector<uint8_t>    _data;
    };

}
