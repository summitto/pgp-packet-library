#pragma once

#include "decoder.h"
#include "encoder.h"
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
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::out_of_range
             */
            multiprecision_integer(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  data    The range of numbers
             */
            multiprecision_integer(gsl::span<const uint8_t> data) noexcept;

            /**
             *  Retrieve the data
             *  @return A span containing all the integer numbers
             */
            gsl::span<const uint8_t> data() const;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            std::vector<uint8_t>    _data;
    };

}
