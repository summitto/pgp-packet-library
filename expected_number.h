#pragma once

#include "decoder.h"


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
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::range_error, std::out_of_range
             */
            expected_number(decoder &parser)
            {
                // check whether the value is as expected
                if (parser.extract_number<T>() != number) {
                    // invalid number was read
                    throw std::range_error{ "A fixed number is incorrect" };
                }
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
    };

}
