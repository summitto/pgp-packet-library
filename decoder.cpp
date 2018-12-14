#include "decoder.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  data    The range to (de|en)code from or to
     */
    decoder::decoder(gsl::span<const uint8_t> data) noexcept :
        _data{ data }
    {}

    /**
     *  Check whether the decoder is empty
     *  @return Whether all encoded data is exhausted
     */
    bool decoder::empty() const noexcept
    {
        // check whether the data stream is empty
        return _data.empty();
    }

    /**
     *  The number of bytes of encoded data still available
     *
     *  @note   This number is rounded up, if some bits of
     *          a byte where consumed, the byte is still counted
     *  @return The available number of bytes
     */
    size_t decoder::size() const noexcept
    {
        // return the number of bytes available
        return _data.size();
    }

    /**
     *  Peek at bits at the current position, but
     *  do not consume them
     *
     *  @param  count   Number of bits to extract
     *  @return The extracted bits
     *  @throws std::out_of_range
     */
    uint8_t decoder::peek_bits(size_t count) const
    {
        // retrieve the current leading byte and mask already-read bytes
        uint8_t result = mask(_data[0]);

        // remove the extra bits from the end
        return result >> (8 - count - _skip_bits);
    }

    /**
     *  Extract bits at the current position
     *
     *  @param  count   Number of bits to extract
     *  @return The extracted bits
     *  @throws std::out_of_range
     */
    uint8_t decoder::extract_bits(size_t count)
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

}
