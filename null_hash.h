#include <cryptopp/cryptlib.h>


namespace pgp {

    /**
     *  A CryptoPP hash transformation that does not actually hash.
     *
     *  The transformation expects an input that is at most the hash size, and
     *  just returns that input when asked for the final hash result.
     */
    template <size_t HASH_SIZE = 32>
    class NullHash : public CryptoPP::HashTransformation
    {
    public:
        /**
         *  The digest size from this hash transformation
         */
        constexpr const static auto DIGESTSIZE = HASH_SIZE;

        /**
         *  The name of the hash algorithm
         */
        static constexpr const char *StaticAlgorithmName()
        {
            return "NullHash";
        }

        /**
         *  The maximum size of the digest produced by this hash transformation
         */
        unsigned int DigestSize() const override
        {
            return DIGESTSIZE;
        }

        /**
         *  Add data to the buffer to be returned when requesting the final hash
         *
         *  The total amount of data submitted to be "hashed" (i.e. returned)
         *  should not be more than the digest size as returned from
         *  DigestSize().
         *
         *  @param input    The data to append to the buffer
         *  @param length   The length of the data in 'input'
         */
        void Update(const CryptoPP::byte *input, size_t length) override
        {
            // If too much data is supplied, throw an exception
            if (length > static_cast<size_t>(std::distance(_iter, _digest.end()))) {
                throw CryptoPP::Exception(
                    CryptoPP::Exception::OTHER_ERROR,
                    "Input to NullHash too large: given " + std::to_string(length) +
                        " while only space left for " + std::to_string(std::distance(_iter, _digest.end()))
                );
            }

            // Append the input data to the "digest" buffer
            _iter = std::copy(input, input + length, _iter);
        }

        /**
         *  Obtain (a prefix of) the inputted data
         *
         *  @param digest     The destination buffer to store the input data in
         *  @param digestSize The size of the "digest" requested; should not be
         *                    more than DigestSize()
         */
        void TruncatedFinal(CryptoPP::byte *digest, size_t digestSize) override
        {
            // Check that the requested digest size is not more than we can provide
            ThrowIfInvalidTruncatedSize(digestSize);

            // Check that we got enough input data to satisfy the request (we
            // allow providing a partial hash as input and then requesting only
            // a prefix of that part)
            if (std::distance(_digest.begin(), _iter) < digestSize) {
                throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "Not enough hash input provided to satisfy request");
            }

            // If we have a buffer to put the data in, copy the data into the destination buffer
            if (digest != nullptr) {
                std::copy(_digest.begin(), std::next(_digest.begin(), digestSize), digest);
            }

            // Reset the digest buffer so that we start a new "hashing" cycle
            _iter = _digest.begin();
        }

    private:
        std::array<uint8_t, DIGESTSIZE> _digest;
        typename std::array<uint8_t, DIGESTSIZE>::iterator _iter{_digest.begin()};
    };

}
