#include "range_encoder.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  data    The range to encode to
     */
    range_encoder::range_encoder(span<uint8_t> data) :
        _data{ data }
    {}

    /**
     *  Flush the encoder, so any partial-written bytes
     *  are written out. Note that after this operation,
     *  bitwise operations start at the beginning again.
     */
    void range_encoder::flush() noexcept
    {
        // do we have any partially-filled bytes?
        if (_skip_bits > 0) {
            // write out the current byte
            _data[_size] = _current;

            // move to the next byte
            ++_size;
            _current = 0;
            _skip_bits = 0;
        }
    }

    /**
     *  Retrieve the number of encoded bytes
     *  @return The number of bytes stored in the encoder
     */
    size_t range_encoder::size() const noexcept
    {
        // return the stored size
        return _size;
    }

    /**
     *  Insert one or more bits
     *
     *  @param  count   The number of bits to insert
     *  @param  value   The value to store in the bits
     *  @return self, for chaining
     *  @throws std::out_of_range, std::range_error
     */
    range_encoder &range_encoder::insert_bits(size_t count, uint8_t value)
    {
        // check whether the number fits within the given bit-size
        if (value > (1U << count) - 1U) {
            // the value is too large to encode
            throw std::range_error{ "Cannot encode value, too large for given bit-size" };
        }

        // the write may not cross a byte boundary
        if (count + _skip_bits > 8) {
            // cannot encode the value, does not fit within byte
            throw std::out_of_range{ "Cannot encode value, bit-wise operation may not cross byte boundaries" };
        }

        if (_size >= _data.size()) {
            // trying to write out-of-bounds
            throw std::out_of_range{ "Buffer too small for inserting bits" };
        }

        // shift the data so it fits with the existing data and add it
        _current |= static_cast<uint8_t>(value << static_cast<uint8_t>(8U - _skip_bits - count));

        // do we move on to the next byte?
        if (count + _skip_bits == 8) {
            // store the byte now
            _data[_size] = _current;
            _current     = 0;

            // move to the next byte
            ++_size;
            _skip_bits = 0;
        } else {
            // just increment the bits to skip
            _skip_bits += count;
        }

        // allow chaining
        return *this;
    }

}
