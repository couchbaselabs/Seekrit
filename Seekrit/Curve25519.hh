//
//  Curve25519.h
//  Seekrit
//
//  Created by Jens Alfke on 8/27/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#ifndef __Seekrit__Curve25519__
#define __Seekrit__Curve25519__

#include <stdint.h>
#include <string.h>
#include <string>

namespace couchbase {
namespace curve25519 {

    /** The raw bytes of a nonce used for encryption. */
    struct Nonce {
        uint8_t bytes[24];

        static Nonce random();
    };

    /** The raw bytes of a digital signature. */
    struct Signature {
        uint8_t bytes[64];
    };


    /** The raw bytes of a Curve25519 key. */
    class Key {
    public:
        Key() {}
        Key(const void* keyBytes)       {::memcpy(const_cast<uint8_t*>(bytes), keyBytes, sizeof(bytes));}
        uint8_t bytes[32];
    };


    class PublicKey : public Key {
    public:
        PublicKey() {}
        PublicKey(const void* keyBytes)       :Key(keyBytes) {}

        bool verifySignature(Signature, std::string input);
        bool verifyDigestSignature(Signature, const void* digest, size_t length);
    };


    class PrivateKey : public Key {
    public:
        static PrivateKey generate();
        PrivateKey(const void* keyBytes);   // also reconstitutes public key

        std::string encrypt(std::string cleartext,  Nonce, const PublicKey& recipient) const;
        std::string decrypt(std::string ciphertext, Nonce, const PublicKey& sender) const;

        Signature sign(std::string);
        Signature signDigest(const void* digest, size_t length);

        PublicKey publicKey;
    };

}
}

#endif /* defined(__Seekrit__Curve25519__) */
