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
     *  @param  key     The key to use for signing
     *  @param  digest  The hash that needs to be signed
     */
    rsa_signature::rsa_signature(const secret_key &key, std::array<uint8_t, 32> &digest)
    {
        // TODO
        throw std::runtime_error{ "Generating RSA signatures is not yet implemeted" };
    }

    /**
     *  Constructor
     *
     *  @param  s       The signature value (m**d mod n)
     */
    rsa_signature::rsa_signature(multiprecision_integer s) noexcept :
        _s{ std::move(s) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool rsa_signature::operator==(const rsa_signature &other) const noexcept
    {
        return s() == other.s();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool rsa_signature::operator!=(const rsa_signature &other) const noexcept
    { return !(*this == other); }

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

}
