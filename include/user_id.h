#pragma once

#include "packet_tag.h"
#include "expected_number.h"
#include "fixed_number.h"
#include "util/span.h"
#include <string>


namespace pgp {

    /**
     *  Class for holding a user id
     */
    class user_id
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The parser to decode data from
             */
            template <class decoder, class = std::enable_if_t<is_decoder_v<decoder>>>
            user_id(decoder &parser) :
                user_id{ parser.template extract_blob<char>(parser.size()) }
            {}

            /**
             *  Constructor
             *
             *  @param  id      The user id to use
             */
            user_id(span<const char> id) noexcept;

            /**
             *  Constructor
             *
             *  @param  id      The user id to use
             */
            user_id(std::string id) noexcept;

            /**
             *  Comparison operators
             *
             *  @param  other   The object to compare with
             */
            bool operator==(const user_id &other) const noexcept;
            bool operator!=(const user_id &other) const noexcept;

            /**
             *  Retrieve the packet tag used for this
             *  packet type
             *  @return The packet type to use
             */
            packet_tag tag() const noexcept
            {
                // this is a user id packet
                return packet_tag::user_id;
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             *  @throws std::runtime_error for unknown key types
             */
            size_t size() const noexcept;

            /**
             *  Retrieve the user id
             *
             *  @return The user id
             */
            const std::string &id() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // insert the id into the encoder
                writer.insert_blob(span<const char>{ _id });
            }
        private:
            std::string     _id;    // the user id representation
    };

}
