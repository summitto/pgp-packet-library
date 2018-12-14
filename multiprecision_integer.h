#pragma once

#include "decoder.h"
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
             *  Retrieve the data
             *  @return A span containing all the integer numbers
             */
            gsl::span<const uint8_t> data() const;
        private:
            std::vector<uint8_t>    _data;
    };

}
