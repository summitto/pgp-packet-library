#include "signature_subpacket/embedded.h"
#include "signature.h"


namespace pgp::signature_subpacket {

    /**
     *  Constructor
     *
     *  @param  value      The value to store
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    embedded<subpacket_type, contained_t>::embedded(contained_t value) :
        _contained{ std::make_unique<contained_t>(value) }
    {}

    /**
     *  Copy constructor
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    embedded<subpacket_type, contained_t>::embedded(const embedded &other) :
        _contained{ std::make_unique<contained_t>(other.contained()) }
    {}

    /**
     *  Move constructor
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    embedded<subpacket_type, contained_t>::embedded(embedded &&other) = default;

    /**
     *  Destructor
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    embedded<subpacket_type, contained_t>::~embedded() = default;

    /**
     *  Copy assignment operator
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    embedded<subpacket_type, contained_t> &
    embedded<subpacket_type, contained_t>::operator=(const embedded &other)
    {
        // copy the contained object
        _contained = std::make_unique<contained_t>(other.contained());

        // allow chaining
        return *this;
    }

    /**
     *  Move assignment operator
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    embedded<subpacket_type, contained_t> &
    embedded<subpacket_type, contained_t>::operator=(embedded &&other) = default;

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    bool embedded<subpacket_type, contained_t>::operator==(const embedded &other) const noexcept
    {
        return type() == other.type() && contained() == other.contained();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    bool embedded<subpacket_type, contained_t>::operator!=(const embedded &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    size_t embedded<subpacket_type, contained_t>::size() const noexcept
    {
        // we need to store the value plus the type
        uint32_t size = _contained->size() + sizeof(type());

        // and then store this number in a variable number
        return size + variable_number{ size }.size();
    }

    /**
     *  Retrieve the stored signature
     *
     *  @return The stored signature
     */
    template <signature_subpacket_type subpacket_type, typename contained_t>
    const contained_t &embedded<subpacket_type, contained_t>::contained() const
    {
        if (_contained) {
            return *_contained;
        } else {
            throw std::runtime_error("contained() on an empty signature_subpacket::embedded");
        }
    }


    /**
     *  Explicit template instantiation for embedded_signature
     */
    template class embedded<signature_subpacket_type::embedded_signature, signature>;

}
