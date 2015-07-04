//
//  CBSigningKey.h
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBKey.h"
@class CBVerifyingPublicKey, CBEncryptingPrivateKey, CBEncryptingPublicKey;


/** An Ed25519 digital signature. (512 bits, 64 bytes) */
typedef struct {
    uint8_t bytes[64];
} CBSignature;


/** An Ed25519 private key used for creating digital signatures.
    Uses the libsodium "crypto_sign" API. */
@interface CBSigningPrivateKey : CBPrivateKey

/** Creates a digital signature of a block of data, using this key.
    (Actually it uses the closely related Ed25519 key.)
    The matching public key can later be used to verify the signature.
    @param input  The data to be signed.
    @return  The 64-byte signature. */
- (CBSignature) signData: (NSData*)input;

/** The corresponding public key. */
@property (readonly) CBVerifyingPublicKey* publicKey;

/** Converts this key into a key that can be used to encrypt data. */
- (CBEncryptingPrivateKey*) asEncryptingKey;

@end



/** A public key used for verifying digital signatures created by its private key. */
@interface CBVerifyingPublicKey : CBPublicKey

/** Verifies that a digital signature was created by this key's matching private signing key.
    @param signature  The signature to be verified.
    @param inputData  The data whose signature is to be verified.
    @return  YES if the signature was created from this input data by the corresponding private
                key; NO if the signature is invalid or doesn't match. */
- (BOOL) verifySignature: (CBSignature)signature
                  ofData: (NSData*)inputData;

/** Converts this key into a public key that can be used to encrypt data. */
- (CBEncryptingPublicKey*) asEncryptingPublicKey;

@end
