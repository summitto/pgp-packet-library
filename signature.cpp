#include "signature.h"


namespace pgp {

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
        _hash_prefix{ parser }
    {
        // what kind of signature should we construct?
        switch (_key_algorithm) {
            case key_algorithm::rsa_encrypt_or_sign:
            case key_algorithm::rsa_sign_only:
                _signature.emplace<rsa_signature>(parser);
                break;
            case key_algorithm::dsa:
                _signature.emplace<dsa_signature>(parser);
                break;
            case key_algorithm::eddsa:
                _signature.emplace<eddsa_signature>(parser);
                break;
            case key_algorithm::ecdsa:
                _signature.emplace<ecdsa_signature>(parser);
                break;
            default:
                // do nothing, use the unknown_key
                break;
        }
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool signature::operator==(const signature &other) const noexcept
    {
        return
            version() == other.version() &&
            type() == other.type() &&
            public_key_algorithm() == other.public_key_algorithm() &&
            hashing_algorithm() == other.hashing_algorithm() &&
            hashed_subpackets() == other.hashed_subpackets() &&
            unhashed_subpackets() == other.unhashed_subpackets() &&
            hash_prefix() == other.hash_prefix() &&
            data() == other.data();
    }

    /**
     *  Comparison operators
     *
     *  @param  other   The object to compare with
     */
    bool signature::operator!=(const signature &other) const noexcept
    {
        return !operator==(other);
    }

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
        result += _hash_prefix.size();

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
     *  Retrieve the 16 most significant bits from the signed hash
     *
     *  @return Two bytes of hash data
     */
    uint16_t signature::hash_prefix() const noexcept
    {
        // return the stored bits
        return _hash_prefix;
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
