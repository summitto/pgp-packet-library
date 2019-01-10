#pragma once

#include "gcrypt_encoder_type.h"


namespace pgp {

    /**
     *  Class for encoding data into a hash context
     */
    template <typename encoder_type_t>
    class gcrypt_encoder
    {
        public:
            /**
             *  Constructor
             */
            gcrypt_encoder()
            {
                // create the digest context
                auto error  = gcry_md_open(&_context, encoder_type_t::algorithm, 0);
                auto code   = gcry_err_code(error);

                // did we get an error?
                if (code) {
                    // @todo: we should be making a more descriptive error!
                    throw std::runtime_error{ "Failed to initialize hasing algorithm" };
                }
            }

            /**
             *  Destructor
             */
            ~gcrypt_encoder()
            {
                // close the hashing context
                gcry_md_close(_context);
            }

            /**
             *  Push a number to the encoder
             *
             *  @param  value   The number to push
             *  @return self, for chaining
             */
            template <typename T>
            typename std::enable_if_t<std::numeric_limits<T>::is_integer, gcrypt_encoder&>
            push(T value) noexcept
            {
                // convert the value to big endian
                auto result = boost::endian::native_to_big(value);

                // add it to the hasher
                gcry_md_write(_context, &result, sizeof result);

                // allow chaining
                return *this;
            }

            /**
             *  Insert an enum
             *
             *  @param  value   The enum to insert
             *  @return self, for chaining
             */
            template <typename T>
            typename std::enable_if_t<std::is_enum<T>::value, gcrypt_encoder&>
            push(T value)
            {
                // cast it to a number and insert it
                return push(static_cast<typename std::underlying_type_t<T>>(value));
            }

            /**
             *  Push a range of data
             *
             *  @param  begin   The iterator to the beginning of the data
             *  @param  end     The iterator to the end of the data
             *  @return self, for chaining
             */
            template <typename iterator_t>
            gcrypt_encoder &push(iterator_t begin, iterator_t end)
            {
                // note: possible c++20 optimization
                // // do we have a contiguous range of memory?
                // if constexpr(std::is_same_v<std::iterator_traits<iterator_t>::iterator_category, std::contiguous_iterator_tag>) {
                //     // push the whole range at once
                //     gcry_md_write(&(*begin), std::distance(begin, end));
                // }

                // iterate over the range
                while (begin != end) {
                    // push the data
                    push(*begin);

                    // move to next element
                    ++begin;
                }

                // allow chaining
                return *this;
            }

            /**
             *  Insert a blob of data
             *
             *  @param  value   The data to insert
             *  @return self, for chaining
             */
            template <typename T>
            gcrypt_encoder &insert_blob(gsl::span<const T> value)
            {
                // add the data to the hasher
                gcry_md_write(_context, value.data(), value.size() * sizeof(T));

                // allow chaining
                return *this;
            }

            /**
             *  Retrieve the final digest
             *
             *  @return The digested data
             */
            std::array<uint8_t, encoder_type_t::digest_size> digest() noexcept
            {
                // create the array for the digest
                std::array<uint8_t, encoder_type_t::digest_size> result;

                // retrieve the result
                auto digest = gcry_md_read(_context, encoder_type_t::algorithm);

                // read the digest into the result
                // std::memcpy(result.data(), digest, result.size());
                std::copy(digest, digest + result.size(), result.begin());

                // return the result
                return result;
            }
        private:
            gcry_md_hd_t    _context    = nullptr;  // the hash context to use
    };

}
