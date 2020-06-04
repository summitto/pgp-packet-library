#include <pgp-packet/packet.h>
#include <iostream>
#include <fstream>
#include <sodium.h>
#include <vector>

int main()
{
    // initialize libsodium
    if (sodium_init() == -1) {
        return 1;
    }

    // create vectors holding the secret and public key points, note
    // that we take an extra byte for the public key, since pgp will
    // need an extra byte in front of it, it is always the same byte
    // for this key type, so it doesn't add any real information but
    // pgp still requires it and throws a fit if it is missing.
    pgp::vector<uint8_t> public_key_data;
    pgp::vector<uint8_t> secret_key_data;

    // allocate memory for the keys
    public_key_data.resize(crypto_sign_PUBLICKEYBYTES + 1);
    secret_key_data.resize(crypto_sign_SECRETKEYBYTES);

    // now create a new keypair to be imported into pgp, as noted in
    // the declaration above, we have to ignore the first byte as we
    // need to set a special tag byte here for pgp to recognize it
    // note: error checks are skipped here for brevity
    crypto_box_keypair(public_key_data.data() + 1, secret_key_data.data());

    // libsodium puts both the secret key and the public key data in
    // the secret key buffer, which pgp does not need, therefore the
    // extra data must be truncated before creating the key
    secret_key_data.resize(32);

    // now set the tag byte required for pgp
    public_key_data[0] = 0x04;

    // define the creation time of this key (as a unix timestamp)
    // and the expiration time (another unix timestamp), we define
    // the key as being valid for 3600 seconds (an hour);
    uint32_t creation = 1559737787;
    uint32_t expiration = creation + 3600;

    // now create a packet containing this secret key
    pgp::packet secret_key_packet{
        pgp::in_place_type_t<pgp::secret_key>{},                        // we are building a secret key
        creation,                                                       // created at this unix timestamp
        pgp::key_algorithm::eddsa,                                      // using the eddsa key algorithm
        pgp::in_place_type_t<pgp::secret_key::eddsa_key_t>{},           // create a key of the eddsa type
        std::forward_as_tuple(                                          // arguments for the public key
            pgp::curve_oid::ed25519(),                                  // which curve to use
            pgp::multiprecision_integer{ std::move(public_key_data) }   // move in the public key point
        ),
        std::forward_as_tuple(                                          // secret arguments
            pgp::multiprecision_integer{ std::move(secret_key_data) }   // copy in the secret key point
        )
    };

    // create a packet describing the user owning this key
    pgp::packet user_id_packet{
        pgp::in_place_type_t<pgp::user_id>{},
        std::string{ "Anne Onymous <anonymous@example.org>" }
    };

    // to complete the set, we need to create a signature packet,
    // which certifies that we are the owners of this key.
    pgp::packet signature_packet{
        pgp::in_place_type_t<pgp::signature>{},                                     // we are making a signature
        pgp::get<pgp::secret_key>(secret_key_packet.body()),                        // we sign it with the secret key
        pgp::get<pgp::user_id>(user_id_packet.body()),                              // for the given user
        pgp::signature_subpacket_set{{                                              // hashed subpackets
            pgp::signature_subpacket::signature_creation_time  { creation      },   // signature creation time
            pgp::signature_subpacket::key_expiration_time      { expiration    },   // key expiration time
            pgp::signature_subpacket::key_flags                { 0x01, 0x02    },   // the privileges for the main key (signing and certification)
        }},
        pgp::signature_subpacket_set{{                                              // unhashed subpackets
            pgp::signature_subpacket::issuer_fingerprint {                          // fingerprint of the key we are signing with
                pgp::get<pgp::secret_key>(secret_key_packet.body()).fingerprint()
            }
        }}
    };

    // we now have a set of packets, which, when encoded to a file, can
    // be imported into a compatible pgp implementation (such as gnupg)
    pgp::vector<uint8_t> data;
    data.resize(
        secret_key_packet   .size() +
        user_id_packet      .size() +
        signature_packet    .size()
    );

    // create an encoder writing in the vectors range
    pgp::range_encoder encoder{ data };

    // encode all the packets into the encoder
    secret_key_packet   .encode(encoder);
    user_id_packet      .encode(encoder);
    signature_packet    .encode(encoder);

    // the encoder has now filled the vector with data, which can be written
    std::ofstream   output{ "keyfile" };
    output.write(reinterpret_cast<const char*>(data.data()), data.size());

    return 0;
}
