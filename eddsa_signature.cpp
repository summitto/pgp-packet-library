#include "eddsa_signature.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    eddsa_signature::eddsa_signature(decoder &parser) :
        _r{ parser },
        _s{ parser }
    {}

    /**
     *  Constructor
     *
     *  @param  r       The EdDSA r value
     *  @param  s       The EdDSA s value
     */
    eddsa_signature::eddsa_signature(multiprecision_integer r, multiprecision_integer s) noexcept :
        _r{ std::move(r) },
        _s{ std::move(s) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t eddsa_signature::size() const noexcept
    {
        // we need space to store both values
        return _r.size() + _s.size();
    }

    /**
     *  Retrieve the EdDSA r value
     *
     *  @return The r value
     */
    const multiprecision_integer &eddsa_signature::r() const noexcept
    {
        // return the r value
        return _r;
    }

    /**
     *  Retrieve the EdDSA s value
     *
     *  @return The s value
     */
    const multiprecision_integer &eddsa_signature::s() const noexcept
    {
        // return the s value
        return _s;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void eddsa_signature::encode(encoder &writer) const
    {
        // encode both values
        _r.encode(writer);
        _s.encode(writer);
    }

}
