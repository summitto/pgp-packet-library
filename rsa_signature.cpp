#include "rsa_signature.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    rsa_signature::rsa_signature(decoder &parser) :
        _s{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  s       The signature value (m**d mod n)
     */
    rsa_signature::rsa_signature(multiprecision_integer s) noexcept :
        _s{ std::move(s) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t rsa_signature::size() const noexcept
    {
        // we only need space for encoding the signature
        return _s.size();
    }

    /**
     *  Retrieve the signature value
     *
     *  @return The signature value (m**d mod n)
     */
    const multiprecision_integer &rsa_signature::s() const noexcept
    {
        // return the signature
        return _s;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void rsa_signature::encode(encoder &writer) const
    {
        // encode the signature
        _s.encode(writer);
    }

}
