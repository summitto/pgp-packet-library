#pragma once

#include <boost/endian/conversion.hpp>
#include <gsl/span>
#include <cstring>
#include <limits>

namespace pgp {

    /**
     *  Class to handle the encoded wire format used
     *  in RFC 4880
     */
    class decoder
    {
        public:
            /**
             *  Constructor
             *
             *  @note   Creates an empty decoder
             */
            decoder() = default;

            /**
             *  Constructor
             *
             *  @param  data    The range to decode from
             */
            decoder(gsl::span<const uint8_t> data) noexcept;

            /**
             *  The decoder is a move-only class
             *
             *  @param  that    The decoder to move
             */
            decoder(const decoder &that) = delete;
            decoder(decoder &&that) = default;

            /**
             *  Assignment operator, only using move
             *
             *  @param  that    The decoder to assign
             */
            decoder &operator=(const decoder &that) = delete;
            decoder &operator=(decoder &&that) = default;

            /**
             *  Splice the data in the decoder into a second decoder
             *
             *  @param  size    Number of bytes to splice off into the other decoder
             *  @return The decoder containing the sliced off data
             *  @throws std::out_of_range
             */
            decoder splice(size_t size);

            /**
             *  Check whether the decoder is empty
             *  @return Whether all encoded data is exhausted
             */
            bool empty() const noexcept;

            /**
             *  The number of bytes of encoded data still available
             *
             *  @note   This number is rounded up, if some bits of
             *          a byte where consumed, the byte is still counted
             *  @return The available number of bytes
             */
            size_t size() const noexcept;

            /**
             *  Peek at bits at the current position, but
             *  do not consume them
             *
             *  @param  count   Number of bits to extract
             *  @return The extracted bits
             *  @throws std::out_of_range
             */
            uint8_t peek_bits(size_t count) const;

            /**
             *  Extract bits at the current position
             *
             *  @param  count   Number of bits to extract
             *  @return The extracted bits
             *  @throws std::out_of_range
             */
            uint8_t extract_bits(size_t count);

            /**
             *  Peek at a number at the current position,
             *  but do not consume it
             *
             *  @return The extracted number
             *  @throws std::out_of_range
             */
            template <typename T>
            T peek_number() const
            {
                // make sure we have enough data for decoding the number
                if (_data.size() < sizeof(T)) {
                    // trying to read out-of-bounds
                    throw std::out_of_range{ "Not enough data available to read number" };
                }

                // the result to copy to
                T result;

                // copy the data to the result value
                std::memcpy(&result, _data.data(), sizeof(T));

                // convert to native endian format and mask it
                boost::endian::big_to_native_inplace(result);

                // mask already-read bytes from the input
                return mask(result);
            }

            /**
             *  Extract a number at the current position
             *
             *  @return The extracted number
             *  @throws std::out_of_range
             */
            template <typename T>
            T extract_number()
            {
                // first extract the number
                auto result = peek_number<T>();

                // and then advance the extracted number of bytes
                _data = _data.subspan<sizeof(T)>();
                _skip_bits = 0;

                // return the result
                return result;
            }
        private:
            /**
             *  Mask the number, removing already-ready bits
             *
             *  @param  number  The number to mask bytes in
             */
            template <typename T>
            T mask(T number) const noexcept
            {
                // create the mask to apply
                auto mask = std::numeric_limits<T>::max() >> _skip_bits;

                // now mask the input and return the result
                return number & mask;
            }

            gsl::span<const uint8_t>    _data;              // the raw data to work with
            uint8_t                     _skip_bits  { 0 };  // number of bits to skip from data
    };

}
