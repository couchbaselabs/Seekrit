//
//  CBSigningKey.m
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBSigningKey.h"
#import "CBKey+Private.h"
#import "sodium.h"


/** libsodium uses a larger key for signing (which actually contains both public & private keys) */
typedef struct {
    uint8_t bytes[crypto_sign_SECRETKEYBYTES];
} CBRawSigningKey;


@implementation CBSigningKey
{
    // Since libsodium wants a larger key structure for signing, I allocate one here.
    // The inherited _rawKey stores the seed, not the actual key.
    CBRawSigningKey _secretKey;
}


@synthesize publicKey=_publicKey;


- (instancetype) init {
    CBKeySeed seed;
    randombytes_buf(&seed, sizeof(seed));
    return [self initWithSeed: seed];
}


- (instancetype)initWithRawKey: (CBRawKey)rawKey {
    CBRawKey pub, secret;
    self = [super initWithRawKey: rawKey];
    if (self) {
        crypto_sign_seed_keypair(pub.bytes, _secretKey.bytes, rawKey.bytes); // rawKey is really seed
        _publicKey = [[CBSigningPublicKey alloc] initWithRawKey: pub];
    }
    return self;
}


- (void) dealloc {
    // Don't leave key data lying around in RAM (remember Heartbleed...)
    memset(&_secretKey, 0, sizeof(_secretKey));
}


- (CBSignature) signData: (NSData*)input {
    NSParameterAssert(input != nil);
    CBSignature signature;
    uint64_t sigLen;
    if (crypto_sign_detached(signature.bytes, &sigLen, input.bytes, input.length, _secretKey.bytes) != 0)
        [NSException raise: NSInternalInconsistencyException
                    format: @"crypto_sign_detached failed"];
    return signature;
}


@end




@implementation CBSigningPublicKey


- (BOOL) verifySignature: (CBSignature)signature
                  ofData: (NSData*)input
{
    NSParameterAssert(input != nil);
    return 0 == crypto_sign_verify_detached(signature.bytes, input.bytes, input.length,
                                            self.rawKey.bytes);
}


@end
