#pragma once

#include <iostream>
#include <optional>
#include <boost/endian/conversion.hpp>
#include <gsl/span>
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
                    throw std::runtime_error{ "Failed to initialize hashing algorithm" };
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
                // if we already computed the digest, return it immediately
                if (_digest) {
                    return *_digest;
                }

                // retrieve the result
                auto result = gcry_md_read(_context, encoder_type_t::algorithm);

                _digest.emplace();

                // read the digest into the digest cache
                std::copy(result, result + _digest->size(), std::begin(*_digest));

                // return the digest
                return *_digest;
            }

            /**
             *  Retrieve the hash prefix: the first two bytes of the digest
             *
             *  @return The hash prefix
             */
            std::array<uint8_t, 2> hash_prefix() noexcept
            {
                // make sure the digest has been computed
                if (!_digest) {
                    digest();
                }

                // obtain the hash prefix
                std::array<uint8_t, 2> prefix;
                std::copy(std::begin(*_digest), std::next(std::begin(*_digest), 2), std::begin(prefix));

                // return the hash prefix
                return prefix;
            }

        private:
            // the hash context to use
            gcry_md_hd_t    _context    = nullptr;

            // the computed digest, once digest() has been called
            std::optional<std::array<uint8_t, encoder_type_t::digest_size>> _digest;
    };

}
