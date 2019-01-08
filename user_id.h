#include "packet_tag.h"
#include "expected_number.h"
#include "fixed_number.h"
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
            template <class encoder_t>
            void encode(encoder_t &writer) const
            {
                // insert the id into the encoder
                writer.insert_blob(gsl::span<const char>{ _id });
            }

            /**
             *  Push the key to the hasher
             *
             *  @param  hasher  The hasher to push the value to
             */
            template <class hasher_t>
            void hash(hasher_t &hasher) const noexcept
            {
                // the magic constant to use for key user id hashing
                static constexpr const expected_number<uint8_t, 0xB4> hash_magic;

                // hash the size of the packet and the data itself
                hash_magic.hash(hasher);
                uint32{ static_cast<uint32_t>(_id.size()) }.hash(hasher);
                hasher.Update(reinterpret_cast<const uint8_t*>(_id.data()), _id.size());
            }
        private:
            std::string     _id;    // the user id representation
    };

}
