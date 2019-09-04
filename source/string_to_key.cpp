#include "string_to_key.h"


namespace pgp {

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool string_to_key::operator==(const string_to_key &other) const noexcept
    {
        return convention() == other.convention();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool string_to_key::operator!=(const string_to_key &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t string_to_key::size() const noexcept
    {
        // return the size of the convention
        return _convention.size();
    }

    /**
     *  Retrieve the convention used
     *
     *  @return The string-to-key convention
     */
    uint8_t string_to_key::convention() const noexcept
    {
        // return the stored convention
        return _convention;
    }

}
