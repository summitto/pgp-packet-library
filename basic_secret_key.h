#pragma once

#include "string_to_key.h"
#include "util/tuple.h"
#include <numeric>


namespace pgp {

    /**
     *  Basic class for holding secret keys
     */
    template <class public_key_t, class secret_key_t>
    class basic_secret_key :
        public public_key_t,
        public string_to_key,
        public secret_key_t
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             */
            basic_secret_key(decoder &parser) :
                public_key_t{ parser },
                string_to_key{ parser },
                secret_key_t{ parser },
                _checksum{ parser }
            {}

            /**
             *  Constructor
             *
             *  @param  public_tuple    Tuple with arguments for constructing the public key
             *  @param  secret_tuple    Tuple with arguments for constructing the secret key
             *  @param  checksum        The checksum of the secret key
             */
            template <class public_arguments, class secret_arguments>
            basic_secret_key(public_arguments &&public_tuple, secret_arguments &&secret_tuple, uint16_t checksum) :
                public_key_t{ util::make_from_tuple<public_key_t>(std::forward<public_arguments>(public_tuple)) },
                secret_key_t{ util::make_from_tuple<secret_key_t>(std::forward<secret_arguments>(secret_tuple)) },
                _checksum{ checksum }
            {}

            /**
             *  Constructor
             *
             *  @param  public_tuple    Tuple with arguments for constructing the public key
             *  @param  secret_tuple    Tuple with arguments for constructing the secret key
             */
            template <class public_arguments, class secret_arguments>
            basic_secret_key(public_arguments &&public_tuple, secret_arguments &&secret_tuple) :
                public_key_t{ util::make_from_tuple<public_key_t>(std::forward<public_arguments>(public_tuple)) },
                secret_key_t{ util::make_from_tuple<secret_key_t>(std::forward<secret_arguments>(secret_tuple)) }
            {
                // data buffer to store the encoded data
                std::vector<uint8_t>    data    { secret_key_t::size()  };
                encoder                 writer  { data                  };

                // encode the secret key data
                secret_key_t::encode(writer);

                // now add up all the numbers to create the checksum
                _checksum = std::accumulate(data.begin(), data.end(), static_cast<uint16_t>(0), [](uint16_t a, uint8_t b) {
                    // add to the current value
                    return a + b;
                });
            }

            /**
             *  Determine the size used in encoded format
             *  @return The number of bytes used for encoded storage
             */
            size_t size() const noexcept
            {
                // get the size of all the components
                return public_key_t::size() + string_to_key::size() + secret_key_t::size() + _checksum.size();
            }

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const
            {
                // encode all the fields
                public_key_t::encode(writer);
                string_to_key::encode(writer);
                secret_key_t::encode(writer);
                _checksum.encode(writer);
            }
        private:
            uint16  _checksum;  // the checksum of the secret data
    };

}
