#include "signature_subpacket_set.h"
#include "variable_number.h"
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
                    _subpackets.emplace_back(mpark::in_place_type_t<signature_creation_time_subpacket>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::signature_expiration_time:
                    // add the signature expiration time
                    _subpackets.emplace_back(mpark::in_place_type_t<signature_expiration_time_subpacket>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::exportable_certification:
                    // store whether this signature is exportable
                    _subpackets.emplace_back(mpark::in_place_type_t<exportable_certification_subpacket>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::key_expiration_time:
                    // add the key expiration time
                    _subpackets.emplace_back(mpark::in_place_type_t<key_expiration_time_subpacket>{}, subpacket_parser);
                    break;
                case signature_subpacket_type::primary_user_id:
                    // add whether this signature constitutes the primary user id
                    _subpackets.emplace_back(mpark::in_place_type_t<primary_user_id_subpacket>{}, subpacket_parser);
                    break;
                default:
                    // add another packet with the remaining data
                    _subpackets.emplace_back(mpark::in_place_type_t<unknown_signature_subpacket>{}, type, subpacket_parser);
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
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     */
    size_t signature_subpacket_set::size() const noexcept
    {
        // allocate size for the header and add size for all the packets
        return std::accumulate(_subpackets.begin(), _subpackets.end(), uint16::size(), [](uint16_t a, const subpacket_variant &b) {
            // retrieve the correct subpacket type
            mpark::visit([&a](auto &&subpacket) {
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
    gsl::span<const signature_subpacket_set::subpacket_variant> signature_subpacket_set::data() const noexcept
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

        // iterate over the subpackets
        for (auto &subpacket : _subpackets) {
            // retrieve the specific type
            mpark::visit([&writer](auto &&subpacket) {
                // encode the subpacket as well
                subpacket.encode(writer);
            }, subpacket);
        }
    }

}
