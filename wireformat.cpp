#include "wireformat.h"
#include <boost/endian/conversion.hpp>
#include <cstring>
#include <limits>


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  data    The range to (de|en)code from or to
     */
    wireformat::wireformat(gsl::span<uint8_t> data) noexcept :
        _data{ data }
    {}

    /**
     *  Peek at bits at the current position, but
     *  do not consume them
     *
     *  @param  count   Number of bits to extract
     *  @return The extracted bits
     *  @throws std::out_of_range
     */
    uint8_t wireformat::peek_bits(size_t count) const
    {
        // retrieve the current leading byte and mask already-read bytes
        uint8_t result = mask(_data[0]);

        // remove the extra bits from the end
        return result >> (8 - count);
    }

    /**
     *  Extract bits at the current position
     *
     *  @param  count   Number of bits to extract
     *  @return The extracted bits
     *  @throws std::out_of_range
     */
    uint8_t wireformat::extract_bits(size_t count)
    {
        // retrieve the current data
        auto result = peek_bits(count);

        // update the bits to skip
        if (_skip_bits + count >= 8) {
            // move on to the next byte
            _data = _data.subspan<1>();
            _skip_bits = 0;
        } else {
            // just update the counter
            _skip_bits += count;
        }

        // return the result
        return result;
    }

    /**
     *  Peek at a number at the current position,
     *  but do not consume it.
     *
     *  @return The extracted number
     *  @throws std::out_of_range
     */
    template <typename T>
    T wireformat::peek_number() const
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
    T wireformat::extract_number()
    {
        // first extract the number
        auto result = peek_number<T>();

        // and then advance the extracted number of bytes
        _data = _data.subspan<sizeof(T)>();
        _skip_bits = 0;

        // return the result
        return result;
    }

    /**
     *  Mask the requested number of bits in the given number
     *
     *  @param  count   Number of bits to mask
     *  @param  number  The number to mask bytes in
     */
    template <typename T>
    T wireformat::mask(T number) const noexcept
    {
        // create the mask to apply
        auto mask = std::numeric_limits<T>::max() >> _skip_bits;

        // now mask the input and return the result
        return number & mask;
    }

}
