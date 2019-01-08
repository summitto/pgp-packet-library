#pragma once

#include "fixed_number.h"
#include <vector>


namespace pgp {

    /**
     *  Class representing a curve object identifier
     */
    class curve_oid
    {
        public:
            /**
             *  Constructor
             */
            curve_oid() = default;

            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::out_of_range
             */
            curve_oid(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  that    The integer to copy or move
             */
            curve_oid(const curve_oid &that) = default;
            curve_oid(curve_oid &&that) = default;

            /**
             *  Assignment
             *
             *  @param  that    The integer to assign
             *  @return Same object for chaining
             */
            curve_oid &operator=(const curve_oid &that) = default;
            curve_oid &operator=(curve_oid &&that) = default;

            /**
             *  Constructor
             *
             *  @param  data    The range of numbers
             */
            curve_oid(gsl::span<const uint8_t> data) noexcept;

            /**
             *  Constructor
             *
             *  @param  data    The range of numbers
             */
            curve_oid(std::initializer_list<const uint8_t> data) noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

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

            /**
             *  Push the curve oid to the hasher
             *
             *  @param  hasher  The hasher to push the value to
             */
            template <class hasher_t>
            void hash(hasher_t &hasher) const noexcept
            {
                // retrieve the size of the curve first
                uint8 size = _data.size();

                // encode the size as well as the data
                size.hash(hasher);
                hasher.Update(_data.data(), _data.size());
            }
        private:
            std::vector<uint8_t>    _data;
    };

}
