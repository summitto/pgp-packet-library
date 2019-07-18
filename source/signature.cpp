#include "signature.h"


namespace pgp {

    /**
     *  Constructor
     *
     *  @param  bound_key               The key we are binding in the signature
     *  @param  user                    The user id we are binding in the signature
     *  @param  hashed_subpackets       The subpackets that will be used for generating the hash
     *  @param  unhashed_subpackets     The subpackets that will not be hashed
     */
    signature::signature(const secret_key &bound_key, const user_id &user, signature_subpacket_set hashed_subpackets, signature_subpacket_set unhashed_subpackets) :
        _type{ signature_type::positive_user_id_and_public_key_certification },
        _key_algorithm{ bound_key.algorithm() },
        _hash_algorithm{ hash_algorithm::sha256 },
        _hashed_subpackets{ std::move(hashed_subpackets) },
        _unhashed_subpackets{ std::move(unhashed_subpackets) }
    {
        visit([&bound_key, &user, this](auto &&key_instance) {
            // obtain the appropriate types
            using signature_t = typename std::decay_t<decltype(key_instance)>::signature_t;
            using encoder_t = typename signature_t::encoder_t;

            // construct the appropriate signature encoder
            encoder_t encoder{bound_key};

            // hash the key
            bound_key.hash(encoder);

            // hash the user id
            encoder.template push<uint8_t>(0xB4);
            encoder.push(util::narrow_cast<uint32_t>(user.size()));
            user.encode(encoder);

            // now hash the signature data itself
            hash_signature(encoder);

            // store the hash prefix
            _hash_prefix = decoder{encoder.hash_prefix()};

            // Directly using emplace would be nice here, but since
            // _signature.emplace is an overloaded member function, this turns
            // out to be surprisingly hard; so hard that an extra move seems
            // worth the increased code clarity.
            _signature.emplace<signature_t>(util::make_from_tuple<signature_t>(encoder.finalize()));
        }, bound_key.key());
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
        visit([&result](auto &data) {
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
