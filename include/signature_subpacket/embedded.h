#pragma once

#include <memory>
#include "../expected_number.h"
#include "../variable_number.h"
#include "../signature_subpacket_type.h"


namespace pgp {
    class signature;
}

namespace pgp::signature_subpacket {

    template <signature_subpacket_type subpacket_type, typename contained_t>
    class embedded
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser     The parser to decode the data
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            embedded(decoder &parser) :
                _contained{ std::make_unique<contained_t>(parser) }
            {
                // all data should be consumed
                if (!parser.empty()) {
                    // this is probably not the correct subpacket type
                    throw std::runtime_error{ "Incorrect subpacket type detected" };
                }
            }

            /**
             *  Constructor
             *
             *  @param  value      The value to store
             */
            embedded(contained_t value);

            /**
             *  Copy and move constructors
             */
            embedded(const embedded &other);
            embedded(embedded &&other);

            /**
             *  Destructor
             */
            ~embedded();

            /**
             *  Assignment operators
             */
            embedded<subpacket_type, contained_t> &operator=(const embedded &other);
            embedded<subpacket_type, contained_t> &operator=(embedded &&other);

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const embedded &other) const noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator!=(const embedded &other) const noexcept;

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept;

            /**
             *  Get the signature subpacket type
             *
             *  @return The type of signature subpacket
             */
            static constexpr signature_subpacket_type type() noexcept
            {
                // return the static type
                return subpacket_type;
            }

            /**
             *  Retrieve the stored value
             *
             *  @return The stored value
             *
             *  @throw std::runtime_error  No contained value is present (after a move)
             */
            const contained_t &contained() const;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // first get the size for the data itself
                uint32_t size = util::narrow_cast<uint32_t>(_contained->size() + sizeof(type()));

                // encode the size and the signature
                variable_number{ size }.encode(writer);
                writer.push(type());
                _contained->encode(writer);
            }

        private:
            std::unique_ptr<contained_t> _contained;
    };

    using embedded_signature = embedded<signature_subpacket_type::embedded_signature, signature>;

}
