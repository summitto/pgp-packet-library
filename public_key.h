#pragma once

#include "decoder.h"
#include "expected_number.h"
#include "public_key_algorithm.h"
#include "multiprecision_integer.h"


namespace pgp {

    /**
     *  Class for managing a public key
     */
    class public_key
    {
        public:
            /**
             *  Constructor
             *
             *  @param  parser  The decoder to parse the data
             *  @throws std::out_of_range
             */
            public_key(decoder &parser);

            /**
             *  Constructor
             *
             *  @param  creation_time   UNIX timestamp the key was created at
             *  @param  algorithm       The key algorithm used
             *  @param  components      The key components
             *  @throws std::runtime_error
             */
            public_key(uint32_t creation_time, public_key_algorithm algorithm, gsl::span<const multiprecision_integer> components);

            /**
             *  Get the key version
             *  @return The key version format
             */
            constexpr uint8_t version() const noexcept
            {
                // extract the value version
                return _version.value();
            }

            /**
             *  Get the creation time
             *  @return UNIX timestamp with key creation time
             */
            uint32_t creation_time() const noexcept;

            /**
             *  Retrieve the key algorithm
             *  @return The algorithm used in the key
             */
            public_key_algorithm algorithm() const noexcept;

            /**
             *  Retrieve the components in the key
             *  @return All the key components
             */
            gsl::span<const multiprecision_integer> components() const noexcept;

            /**
             *  Write the data to an encoder
             *
             *  @param  writer  The encoder to write to
             *  @throws std::out_of_range, std::range_error
             */
            void encode(encoder &writer) const;
        private:
            expected_number<uint8_t, 4>         _version;               // the expected key version format
            uint32_t                            _creation_time  { 0 };  // UNIX timestamp the key was created at
            public_key_algorithm                _algorithm      { 0 };  // the algorithm for creating the key
            std::vector<multiprecision_integer> _components;            // the algorithm-specific components of the key

    };
}
