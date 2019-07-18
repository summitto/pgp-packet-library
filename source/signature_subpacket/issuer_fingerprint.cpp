#include "signature_subpacket/issuer_fingerprint.h"


namespace pgp::signature_subpacket {

    /**
     *  Constructor
     *
     *  @param  data    The array of data
     */
    issuer_fingerprint::issuer_fingerprint(std::array<uint8_t, fingerprint_size> data) noexcept :
        _data{ data }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool issuer_fingerprint::operator==(const issuer_fingerprint &other) const noexcept
    {
        return data() == other.data();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool issuer_fingerprint::operator!=(const issuer_fingerprint &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t issuer_fingerprint::size() const noexcept
    {
        // we need to store the number, together with the type and the key version
        uint32_t size = util::narrow_cast<uint32_t>(_data.size() + _version.size() + sizeof(type()));

        // and then store this number in a variable number
        return size + variable_number{ size }.size();
    }

    /**
     *  Retrieve the stored array
     *
     *  @return The stored array
     */
    const std::array<uint8_t, issuer_fingerprint::fingerprint_size> &issuer_fingerprint::data() const noexcept
    {
        // retrieve the stored array
        return _data;
    }

}
