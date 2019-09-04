#include "curve_oid.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  data    The range of numbers
     */
    curve_oid::curve_oid(span<const uint8_t> data) noexcept :
        _data{ data.begin(), data.end() }
    {}

    /**
     *  Constructor
     *
     *  @param  data    The range of numbers
     */
    curve_oid::curve_oid(std::initializer_list<const uint8_t> data) noexcept :
        _data{ data.begin(), data.end() }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool curve_oid::operator==(const curve_oid &other) const noexcept
    {
        return data() == other.data();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool curve_oid::operator!=(const curve_oid &other) const noexcept
    {
        return !operator==(other);
    }

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
    span<const uint8_t> curve_oid::data() const
    {
        // provide access to the underlying data
        return _data;
    }

}
