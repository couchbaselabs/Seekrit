//
//  Curve25519.cpp
//  Seekrit
//
//  Created by Jens Alfke on 8/27/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#include "Curve25519.hh"
#include "tweetnacl.h"
#include "curve_sigs.h"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <Security/SecRandom.h>


namespace couchbase {
namespace curve25519 {

    static uint8_t* allocPadded(std::string original, size_t paddingSize);
    static std::string unpad(std::string padded, size_t paddingSize);


    template <typename T>
    inline T randomized() {
        T t;
        SecRandomCopyBytes(kSecRandomDefault, sizeof(t), &t);
        return t;
    }

    PrivateKey PrivateKey::generate() {
        Key k = randomized<Key>();
        return PrivateKey(&k);
    }

    PrivateKey::PrivateKey(const void* keyBytes)
    :Key(keyBytes)
    {
        // A few bits need to be adjusted to make this into a valid Curve25519 key:
        bytes[ 0] &= 248;
        bytes[31] &= 63;
        bytes[31] |= 64;

        crypto_scalarmult_base(publicKey.bytes, bytes);  // recover public key
    }

    std::string PrivateKey::encrypt(std::string cleartext,
                                    Nonce nonce,
                                    const PublicKey& recipient) const
    {
        size_t msgLen = crypto_box_ZEROBYTES + cleartext.size();
        uint8_t* paddedCleartext = allocPadded(cleartext, crypto_box_ZEROBYTES);
        NSMutableData* ciphertext = [NSMutableData dataWithLength: msgLen];
        crypto_box(ciphertext.mutableBytes, paddedCleartext, msgLen, nonce.bytes,
                   recipient.rawKey.bytes, _rawKey.bytes);
        free(paddedCleartext);
        return unpad(ciphertext, crypto_box_BOXZEROBYTES);
    }

    std::string PrivateKey::decrypt(std::string ciphertext,
                                    Nonce nonce,
                                    const PublicKey& sender) const
    {

    }

    Signature PrivateKey::sign(std::string);
    Signature PrivateKey::signDigest(const void* digest, size_t length);



    // mallocs a block with `paddingSize` zero bytes followed by `original`.
    static uint8_t* allocPadded(std::string original, size_t paddingSize) {
        size_t length = original.size();
        uint8_t* padded = (uint8_t*)::malloc(paddingSize + length);
        memset(padded, 0, paddingSize);
        memcpy(padded + paddingSize, original.bytes, length);
        return padded;
    }

    // Strips the first `paddingSize` bytes from `padded`, returning `padded`.
    static NSData* unpad(NSMutableData* padded, size_t paddingSize) {
        size_t length = padded.length - paddingSize;
        memmove(padded.mutableBytes, padded.mutableBytes + paddingSize, length);
        padded.length = length;
        return padded;
    }
    

}
}
