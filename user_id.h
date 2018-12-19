#include "packet_tag.h"
#include "decoder.h"
#include "encoder.h"
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
            user_id(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  id      The user id to use
             */
            user_id(gsl::span<const char> id) noexcept;

            /**
             *  Constructor
             *
             *  @param  id      The user id to use
             */
            user_id(std::string id) noexcept;

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
            void encode(encoder &writer) const;
        private:
            std::string     _id;    // the user id representation
    };

}
