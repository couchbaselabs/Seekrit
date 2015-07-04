//
//  CBEncryptingKey.m
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//
//  <https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html>

#import "CBEncryptingPrivateKey.h"
#import "CBKey+Private.h"
#import "sodium.h"


@implementation CBEncryptingPublicKey
@end



@implementation CBEncryptingPrivateKey


@synthesize publicKey=_publicKey;


- (instancetype) init {
    CBRawKey priv, pub;
    crypto_box_keypair(pub.bytes, priv.bytes);
    self = [super initWithRawKey: priv];
    if (self) {
        _publicKey = [[CBEncryptingPublicKey alloc] initWithRawKey: pub];
    }
    return self;
}


- (instancetype) initWithRawKey: (CBRawKey)rawKey {
    self = [super initWithRawKey: rawKey];
    if (self) {
        CBRawKey pub;
        crypto_scalarmult_base(pub.bytes, rawKey.bytes);
        _publicKey = [[CBEncryptingPublicKey alloc] initWithRawKey: pub];
    }
    return self;
}


- (instancetype) initWithSeed: (CBKeySeed)seed {
    CBRawKey pub, priv;
    crypto_box_seed_keypair(pub.bytes, priv.bytes, seed.bytes);
    self = [super initWithRawKey: priv];
    if (self) {
        _publicKey = [[CBEncryptingPublicKey alloc] initWithRawKey: pub];
    }
    return self;
}


- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (CBNonce)nonce
       forRecipient: (CBEncryptingPublicKey*)recipient
{
    NSParameterAssert(recipient != nil);

    size_t clearLen = cleartext.length;
    size_t cipherLen = clearLen + crypto_box_MACBYTES;
    void* ciphertext = malloc(cipherLen);
    crypto_box_easy(ciphertext, cleartext.bytes, clearLen, nonce.bytes,
                    recipient.rawKey.bytes, self.rawKey.bytes);
    return [NSData dataWithBytesNoCopy: ciphertext length: cipherLen freeWhenDone: YES];
}


- (void) encrypt: (NSData*)cleartext
       withNonce: (CBNonce)nonce
    forRecipient: (CBEncryptingPublicKey*)recipient
        appendTo: (NSMutableData*)output
{
    NSParameterAssert(recipient != nil);

    size_t clearLen = cleartext.length;
    size_t cipherLen = clearLen + crypto_box_MACBYTES;
    size_t outputLen = output.length;

    output.length += cipherLen;
    void* ciphertext = (uint8_t*)output.bytes + outputLen;

    crypto_box_easy(ciphertext, cleartext.bytes, clearLen, nonce.bytes,
                    recipient.rawKey.bytes, self.rawKey.bytes);
}


- (NSData*) decrypt: (NSData*)ciphertext
          withNonce: (CBNonce)nonce
         fromSender: (CBEncryptingPublicKey*)sender
{
    NSParameterAssert(ciphertext != nil);
    NSParameterAssert(sender != nil);

    if (ciphertext.length < crypto_box_MACBYTES)
        return nil;
    size_t msgLen = ciphertext.length - crypto_box_MACBYTES;
    NSMutableData* cleartext = [NSMutableData dataWithLength: msgLen];
    if (0 != crypto_box_open_easy(cleartext.mutableBytes, ciphertext.bytes, ciphertext.length,
                                  nonce.bytes, sender.rawKey.bytes, self.rawKey.bytes))
        return nil;
    return cleartext;
}


@end
