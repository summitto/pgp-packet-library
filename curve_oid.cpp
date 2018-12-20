#include "curve_oid.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     *  @throws std::out_of_range
     */
    curve_oid::curve_oid(decoder &parser)
    {
        // first read the number of elements
        auto count = parser.extract_number<uint8_t>();

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
    curve_oid::curve_oid(gsl::span<const uint8_t> data) noexcept :
        _data{ data.begin(), data.end() }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t curve_oid::size() const noexcept
    {
        // one byte for the header, plus the data itself
        return _data.size() + 1;
    }

    /**
     *  Retrieve the data
     *  @return A span containing all the integer numbers
     */
    gsl::span<const uint8_t> curve_oid::data() const
    {
        // provide access to the underlying data
        return _data;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void curve_oid::encode(encoder &writer) const
    {
        // write out the number of elements first
        writer.insert_number(static_cast<uint8_t>(_data.size()));

        // now add all the elements
        for (auto number : _data) {
            // add the number
            writer.insert_number(number);
        }
    }

}