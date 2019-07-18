#pragma once

#include "signature_subpacket/issuer_fingerprint.h"
#include "signature_subpacket/fixed_array.h"
#include "signature_subpacket/key_flags.h"
#include "signature_subpacket/embedded.h"
#include "signature_subpacket/unknown.h"
#include "signature_subpacket/numeric.h"
#include "signature_subpacket_type.h"
#include "util/variant.h"


namespace pgp {

    /**
     *  Class holding a set of signature subpackets
     */
    class signature_subpacket_set
    {
        public:
            /**
             *  The recognized subpacket types
             */
            using subpacket_variant = variant<
                signature_subpacket::unknown,
                signature_subpacket::issuer,
                signature_subpacket::signature_creation_time,
                signature_subpacket::signature_expiration_time,
                signature_subpacket::exportable_certification,
                signature_subpacket::primary_user_id,
                signature_subpacket::key_expiration_time,
                signature_subpacket::key_flags,
                signature_subpacket::issuer_fingerprint,
                signature_subpacket::embedded_signature
            >;

            /**
             *  Default constructor
             */
            signature_subpacket_set() = default;

            /**
             *  Constructor
             *
             *  @param  parser      The decoder to parse the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            signature_subpacket_set(decoder &parser)
            {
                // splice off the allocated data from the main parser
                auto set_parser = parser.splice(uint16{ parser });

                // now read all the data in the subpackets
                while (!set_parser.empty()) {
                    // read the length and type of the subpacket
                    uint32_t length = variable_number           { set_parser                                    };
                    auto     type   = signature_subpacket_type  { set_parser.template extract_number<uint8_t>() };

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
            signature_subpacket_set(std::vector<subpacket_variant> subpackets) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const pgp::signature_subpacket_set &other) const noexcept;
            bool operator!=(const pgp::signature_subpacket_set &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Iterator access to the subpackets
             */
            auto begin()    const noexcept { return _subpackets.cbegin();   }
            auto cbegin()   const noexcept { return _subpackets.cbegin();   }
            auto rbegin()   const noexcept { return _subpackets.crbegin();  }
            auto crbegin()  const noexcept { return _subpackets.crbegin();  }
            auto end()      const noexcept { return _subpackets.cend();     }
            auto cend()     const noexcept { return _subpackets.cend();     }
            auto rend()     const noexcept { return _subpackets.crend();    }
            auto crend()    const noexcept { return _subpackets.crend();    }

            /**
             *  Retrieve a specific subpacket
             *
             *  @param  offset  The offset for the subpacket to receive
             *  @throws std::out_of_range
             */
            const subpacket_variant &operator[](size_t offset) const;

            /**
             *  Retrieve all subpackets
             *
             *  @return The subpackets in the set
             */
            span<const subpacket_variant> data() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // add the size header; this is the size of the packet minus
                // the size of the header itself
                uint16{ util::narrow_cast<uint16_t>(size() - uint16::size()) }.encode(writer);

                // iterate over the subpackets
                for (auto &subpacket : _subpackets) {
                    // retrieve the specific type
                    visit([&writer](auto &&subpacket) {
                        // encode the subpacket as well
                        subpacket.encode(writer);
                    }, subpacket);
                }
            }
        private:
            std::vector<subpacket_variant>  _subpackets;    // the subpackets in the set
    };

}
