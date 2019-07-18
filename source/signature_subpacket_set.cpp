#include "signature_subpacket_set.h"
#include "variable_number.h"
#include "fixed_number.h"
#include "signature.h"
#include <numeric>


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  subpackets  The subpackets to keep in the set
     */
    signature_subpacket_set::signature_subpacket_set(std::vector<subpacket_variant> subpackets) noexcept :
        _subpackets{ std::move(subpackets) }
    {}

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool signature_subpacket_set::operator==(const pgp::signature_subpacket_set &other) const noexcept
    {
        return data() == other.data();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool signature_subpacket_set::operator!=(const pgp::signature_subpacket_set &other) const noexcept
    {
        return !operator==(other);
    }

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t signature_subpacket_set::size() const noexcept
    {
        // allocate size for the header and add size for all the packets
        return std::accumulate(_subpackets.begin(), _subpackets.end(), uint16::size(), [](uint16_t a, const subpacket_variant &b) {
            // retrieve the correct subpacket type
            visit([&a](auto &&subpacket) {
                // add the size of the subpacket
                a += subpacket.size();
            }, b);

            // return the increased size
            return a;
        });
    }

    /**
     *  Retrieve a specific subpacket
     *
     *  @param  offset  The offset for the subpacket to receive
     *  @throws std::out_of_range
     */
    const signature_subpacket_set::subpacket_variant &signature_subpacket_set::operator[](size_t offset) const
    {
        // retrieve subpacket at requested offset
        return _subpackets[offset];
    }

    /**
     *  Retrieve all subpackets
     *
     *  @return The subpackets in the set
     */
    span<const signature_subpacket_set::subpacket_variant> signature_subpacket_set::data() const noexcept
    {
        // return the stored subpackets
        return _subpackets;
    }

}
