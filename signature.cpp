#include "signature.h"


namespace pgp {

    namespace {
        /**
         *  Construct the signature variant
         *
         *  @param  algorithm   The key algorithm
         *  @param  parser      The decoder to parse the data
         */
        signature::signature_variant construct_signature(key_algorithm algorithm, decoder &parser)
        {
            // check the provided algorithm
            switch (algorithm) {
                case key_algorithm::rsa_encrypt_or_sign:
                case key_algorithm::rsa_sign_only:
                    return rsa_signature{ parser };
                case key_algorithm::dsa:
                    return dsa_signature{ parser };
                case key_algorithm::eddsa:
                    return eddsa_signature{ parser };
                default:
                    throw std::runtime_error{ "Unknown signature type" };
            }
        }
    }

    /**
     *  Constructor
     *
     *  @param  parser  The decoder to parse the data
     */
    signature::signature(decoder &parser) :
        _version{ parser },
        _type{ parser.extract_number<uint8_t>() },
        _key_algorithm{ parser.extract_number<uint8_t>() },
        _hash_algorithm{ parser.extract_number<uint8_t>() },
        _hashed_subpackets{ parser },
        _unhashed_subpackets{ parser },
        _signature_bits{ parser },
        _signature{ construct_signature(_key_algorithm, parser) }
    {}

    /**
     *  Determine the size used in encoded format
     *  @return The number of bytes used for encoded storage
     *  @throws std::runtime_error for unknown signature types
     */
    size_t signature::size() const
    {
        // the size of all the components
        size_t result{ 0 };

        // add components
        result += _version.size();
        result += sizeof(_type);
        result += sizeof(_key_algorithm);
        result += sizeof(_hash_algorithm);
        result += _hashed_subpackets.size();
        result += _unhashed_subpackets.size();
        result += _signature_bits.size();

        // retrieve the signature
        mpark::visit([&result](auto &data) {
            // add the signature size to the total
            result += data.size();
        }, _signature);

        // return the total size
        return result;
    }

    /**
     *  Get the signature type
     *  @return The type of signature
     */
    signature_type signature::type() const noexcept
    {
        // return the stored type
        return _type;
    }

    /**
     *  Get the used key algorithm
     *
     *  @return The public key algorithm
     */
    key_algorithm signature::public_key_algorithm() const noexcept
    {
        // return the stored key algorithm
        return _key_algorithm;
    }

    /**
     *  Get the used hashing algorithm
     *
     *  @return The hashing algorithm
     */
    hash_algorithm signature::hashing_algorithm() const noexcept
    {
        // return the stored hashing algorithm
        return _hash_algorithm;
    }

    /**
     *  Retrieve the hashed subpackets
     *
     *  @return The hashed subpackets
     */
    const signature_subpacket_set &signature::hashed_subpackets() const noexcept
    {
        // return the stored hashed subpackets
        return _hashed_subpackets;
    }

    /**
     *  Retrieve the unhashed subpackets
     *
     *  @return The unhashed subpackets
     */
    const signature_subpacket_set &signature::unhashed_subpackets() const noexcept
    {
        // return the stored unhashed subpackets
        return _unhashed_subpackets;
    }

    /**
     *  Retrieve the signature data
     *
     *  @return The signature data
     */
    const signature::signature_variant &signature::data() const noexcept
    {
        // return the stored signature
        return _signature;
    }

}
