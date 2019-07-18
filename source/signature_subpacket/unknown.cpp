#include "signature_subpacket/unknown.h"


namespace pgp::signature_subpacket {

    /**
     *  Constructor
     *
     *  @param  type    The signature subpacket type
     *  @param  data    The data contained in the subpacket
     */
    unknown::unknown(signature_subpacket_type type, span<const uint8_t> data) :
        _type{ type },
        _data{ data.begin(), data.end() }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool unknown::operator==(const unknown &other) const noexcept
    {
        return _data.size() == other._data.size() && std::equal(_data.begin(), _data.end(), other._data.begin());
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool unknown::operator!=(const unknown &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t unknown::size() const noexcept
    {
        // we need to encode the type and the data and encode that
        // size again using variable-length packet encoding
        uint32_t size = util::narrow_cast<uint32_t>(sizeof(_type) + _data.size());

        // now add the size necessary to encode the size itself
        return size + variable_number{ size }.size();
    }

    /**
     *  Get the signature subpacket type
     *  @return The type of signature subpacket
     */
    signature_subpacket_type unknown::type() const noexcept
    {
        // return the stored type
        return _type;
    }

    /**
     *  Retrieve the data
     *  @return A span containing all the integer numbers
     */
    span<const uint8_t> unknown::data() const noexcept
    {
        // return the stored data
        return _data;
    }

}
