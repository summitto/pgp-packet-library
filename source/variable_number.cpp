#include "variable_number.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  value   The value to hold
     */
    variable_number::variable_number(uint32_t value) noexcept :
        _value{ value }
    {}

    /**
     *  Assignment operator
     *
     *  @param  value   The value to assign
     *  @return self, for chaining
     */            
    variable_number &variable_number::operator=(uint32_t value) noexcept
    {              
        // update value
        _value = value;

        // allow chaining
        return *this;
    }

    /**
     *  Determine the size used in encoded format
     *
     *  @return The number of bytes used for encoded storage
     */
    size_t variable_number::size() const noexcept
    {
        // size depends on the stored value
        if (_value < 192) {
            // this can be done in a single octet
            return 1;
        } else if (_value < 8384) {
            // this will use two octets
            return 2;
        } else {
            // we will use five octets instead
            return 5;
        }
    }

    /**
     *  Extract the stored value
     *
     *  @return The stored value
     */
    variable_number::operator uint32_t() const noexcept
    {
        // return the stored value
        return _value;
    }

}
