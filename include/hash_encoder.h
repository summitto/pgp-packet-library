#pragma once

#include <boost/endian/conversion.hpp>
#include <cryptopp/sha.h>
#include "util/span.h"


namespace pgp {

    /**
     *  Class for encoding data into a hash context
     */
    template <class hasher_t>
    class hash_encoder
    {
        public:
            /**
             *  Constructor
             */
            hash_encoder() = default;

            /**
             *  Retrieve the underlying hash context
             *
             *  @return The hash context
             */
            hasher_t &hash_context() noexcept
            {
                // return the stored context
                return _hasher;
            }

            /**
             *  Push a number to the encoder
             *
             *  @param  value   The number to push
             *  @return self, for chaining
             */
            template <typename T>
            typename std::enable_if_t<std::numeric_limits<T>::is_integer, hash_encoder&>
            push(T value) noexcept
            {
                // convert the value to big endian
                auto result = boost::endian::native_to_big(value);

                // add it to the hasher
                _hasher.Update(reinterpret_cast<const uint8_t*>(&result), sizeof result);

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
            typename std::enable_if_t<std::is_enum<T>::value, hash_encoder&>
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
            hash_encoder &push(iterator_t begin, iterator_t end)
            {
                // note: possible c++20 optimization
                // // do we have a contiguous range of memory?
                // if constexpr(std::is_same_v<std::iterator_traits<iterator_t>::iterator_category, std::contiguous_iterator_tag>) {
                //     // push the whole range at once
                //     _hasher.Update(&(*begin), std::distance(begin, end));
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
            hash_encoder &insert_blob(span<const T> value)
            {
                // add the data to the hasher
                _hasher.Update(reinterpret_cast<const uint8_t*>(value.data()), value.size() * sizeof(T));

                // allow chaining
                return *this;
            }

            /**
             *  Retrieve the final digest
             *
             *  @return The digested data
             */
            std::array<uint8_t, hasher_t::DIGESTSIZE> digest() noexcept
            {
                // do we still have to finalize the result
                if (!_finalized) {
                    // fill the data array
                    _hasher.Final(_data.data());

                    // we have now been finalized
                    _finalized = true;
                }

                // return the result
                return _data;
            }

            /**
             *  Retrieve the hash prefix: the first two bytes of the digest
             *
             *  @return The hash prefix
             */
            std::array<uint8_t, 2> hash_prefix() noexcept
            {
                // the resulting prefix
                std::array<uint8_t, 2> prefix;

                // fill it with the data
                std::copy_n(digest().begin(), prefix.size(), prefix.begin());

                // return the hash prefix
                return prefix;
            }
        private:
            hasher_t                                    _hasher;                // the hash context to push to
            bool                                        _finalized  { false };  // did we already finalize the result
            std::array<uint8_t, hasher_t::DIGESTSIZE>   _data;                  // the finalized hash data
    };

    /**
     *  Concrete hasher types
     */
    using sha1_encoder      = hash_encoder<CryptoPP::SHA1>;
    using sha256_encoder    = hash_encoder<CryptoPP::SHA256>;

}
