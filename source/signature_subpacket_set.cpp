#include "signature_subpacket_set.h"
#include "variable_number.h"
#include "fixed_number.h"
#include "signature.h"
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
        auto set_parser = parser.splice(uint16{ parser });

        // now read all the data in the subpackets
        while (!set_parser.empty()) {
            // read the length and type of the subpacket
            uint32_t length = variable_number           { set_parser                            };
            auto     type   = signature_subpacket_type  { set_parser.extract_number<uint8_t>()  };

            // the length includes the type - which we already parsed
            --length;

            // now create a parser specially for the packet
            auto subpacket_parser = set_parser.splice(length);

            // what subpacket type are we creating?
            switch (type) {
                case signature_subpacket_type::signature_creation_time:
                    // add the signature creation time
                    _subpackets.emplace_back(in_place_type_t<signature_subpacket::signature_creation_time>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::issuer:
                    // add the issuer key id
                    _subpackets.emplace_back(in_place_type_t<signature_subpacket::issuer>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::signature_expiration_time:
                    // add the signature expiration time
                    _subpackets.emplace_back(in_place_type_t<signature_subpacket::signature_expiration_time>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::exportable_certification:
                    // store whether this signature is exportable
                    _subpackets.emplace_back(in_place_type_t<signature_subpacket::exportable_certification>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::key_expiration_time:
                    // add the key expiration time
                    _subpackets.emplace_back(in_place_type_t<signature_subpacket::key_expiration_time>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::primary_user_id:
                    // add whether this signature constitutes the primary user id
                    _subpackets.emplace_back(in_place_type_t<signature_subpacket::primary_user_id>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::key_flags:
                    // add the flags for this subpacket
                    _subpackets.emplace_back(in_place_type_t<signature_subpacket::key_flags>{}, subpacket_parser);
                    break;
                default:
                    // add another packet with the remaining data
                    _subpackets.emplace_back(in_place_type_t<signature_subpacket::unknown>{}, type, subpacket_parser);
                    break;
            }
        }
    }

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
