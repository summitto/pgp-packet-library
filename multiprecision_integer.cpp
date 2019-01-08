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
        // eliminate leading zeroes
        while (!data.empty() && data[0] == 0) {
            // detected zero entry - eliminating
            data = data.subspan<1>();
        }

        // assign bit count and the data
        // TODO: count leading zeroes
        _bits = data.size() * 8;
        _data.assign(data.begin(), data.end());
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

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void multiprecision_integer::encode(encoder &writer) const
    {
        // write out the number of elements first
        _bits.encode(writer);

        // now write out all the elements
        for (auto number : _data) {
            // add the number
            writer.insert_number(number);
        }
    }

}
