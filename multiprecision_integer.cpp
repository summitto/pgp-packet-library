#include "multiprecision_integer.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     *  @throws std::out_of_range
     */
    multiprecision_integer::multiprecision_integer(decoder &parser) :
        _bits{ parser }
    {
        // first read the number of elements, since it is in bits,
        // we have to round it up to the nearest byte and read it
        auto count = (_bits + 7) / 8;

        // allocate memory for the number
        _data.reserve(count);

        // and now read all the elements
        while (_data.size() < count) {
            // add an element
            _data.push_back(parser.extract_number<uint8_t>());
        }
    }

    /**
     *  Constructor
     *
     *  @param  data    The range of numbers
     */
    multiprecision_integer::multiprecision_integer(gsl::span<const uint8_t> data) noexcept
    {
        // assign the data
        operator=(data);
    }


    /**
     *  Assignment
     *
     *  @param  that    The integer to assign
     *  @return Same object for chaining
     */
    multiprecision_integer &multiprecision_integer::operator=(gsl::span<const uint8_t> data) noexcept
    {
        // eliminate leading zeroes
        while (!data.empty() && data[0] == 0) {
            // detected zero entry - eliminating
            data = data.subspan<1>();
        }

        // if there is no data we have nothing to do
        if (data.empty()) {
            // no need to calculate anything
            return *this;
        }

        // lookup table for number of leading zeroes
        static constexpr std::array<uint8_t, 16> clz_lookup{ 4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 };

        // split the number up into the upper- and lower 4-bit bounds
        auto upper = data[0] >> 4;
        auto lower = data[0] & 0x0F;

        // calculate number of leading zeroes
        auto leading_zeroes = upper ? clz_lookup[upper] : 4 + clz_lookup[lower];

        // assign bit count and the data
        _bits = data.size() * 8 - leading_zeroes;
        _data.assign(data.begin(), data.end());

        // allow chaining
        return *this;
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t multiprecision_integer::size() const noexcept
    {
        // two bytes for the header plus all the fields
        return _bits.size() + _data.size();
    }

    /**
     *  Retrieve the data
     *  @return A span containing all the integer numbers
     */
    gsl::span<const uint8_t> multiprecision_integer::data() const noexcept
    {
        // provide access to the underlying vector
        return _data;
    }

}
