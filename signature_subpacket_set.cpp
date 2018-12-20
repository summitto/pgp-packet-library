#include "signature_subpacket_set.h"
#include "fixed_number.h"
#include <numeric>


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  parser      The decoder to parse the data
     */
    signature_subpacket_set::signature_subpacket_set(decoder &parser)
    {
        // splice off the allocated data from the main parser
        auto subpacket_parser = parser.splice(uint16{ parser });

        // now read all the data in the subpackets
        while (!subpacket_parser.empty()) {
            // add another packet with the remaining data
            _subpackets.emplace_back(subpacket_parser);
        }
    }

    /**
     *  Constructor
     *
     *  @param  subpackets  The subpackets to keep in the set
     */
    signature_subpacket_set::signature_subpacket_set(gsl::span<signature_subpacket> subpackets) noexcept :
        _subpackets{ subpackets.begin(), subpackets.end() }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t signature_subpacket_set::size() const noexcept
    {
        // allocate size for the header and add size for all the packets
        return std::accumulate(_subpackets.begin(), _subpackets.end(), uint16::size(), [](uint16_t a, const signature_subpacket &b) {
            // add the subpacket size
            return a + b.size();
        });
    }

    /**
     *  Retrieve a specific subpacket
     *
     *  @param  offset  The offset for the subpacket to receive
     *  @throws std::out_of_range
     */
    const signature_subpacket &signature_subpacket_set::operator[](size_t offset) const
    {
        // retrieve subpacket at requested offset
        return _subpackets[offset];
    }

    /**
     *  Retrieve all subpackets
     *
     *  @return The subpackets in the set
     */
    gsl::span<const signature_subpacket> signature_subpacket_set::data() const noexcept
    {
        // return the stored subpackets
        return _subpackets;
    }

    /**
     *  Write the data to an encoder
     *
     *  @param  writer  The encoder to write to
     *  @throws std::out_of_range, std::range_error
     */
    void signature_subpacket_set::encode(encoder &writer) const
    {
        // the size of the packet - but without the size of the header itself
        uint16_t data_size = size() - uint16::size();

        // add the size header
        uint16{ data_size }.encode(writer);

        // now encode all the subpackets themselves
        for (auto &subpacket : _subpackets) {
            // encode the subpacket
            subpacket.encode(writer);
        }
    }

}
