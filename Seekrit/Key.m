//
//  Key.m
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

// http://cr.yp.to/ecdh.html
// http://nacl.cr.yp.to/box.html


#import "Key.h"
#import "tweetnacl.h"
#import "curve_sigs.h"


// External function called by tweetnacl.c
void randombytes(uint8_t* bytes, uint64_t count) {
    SecRandomCopyBytes(kSecRandomDefault, (size_t)count, bytes);
}




@implementation Key
{
    @protected
    RawKey _rawKey;
}

@synthesize rawKey=_rawKey;

+ (PrivateKey*) generateKeyPair {
    RawKey priv;
    SecRandomCopyBytes(kSecRandomDefault, sizeof(priv), priv.bytes);
    return [[PrivateKey alloc] initWithRawKey: priv];
}

- (instancetype) initWithRawKey: (RawKey)rawKey {
    self = [super init];
    if (self) {
        _rawKey = rawKey;
    }
    return self;
}

- (instancetype) initWithKeyData: (NSData*)keyData
{
    if (keyData.length != sizeof(RawKey))
        return nil;
    return [self initWithRawKey: *(const RawKey*)keyData.bytes];
}

- (NSData*) keyData {
    return [NSData dataWithBytes: &_rawKey length: sizeof(_rawKey)];
}


@end




@implementation PrivateKey


@synthesize publicKey=_publicKey;


- (instancetype)initWithRawKey:(RawKey)rawKey {
    // A few bits need to be adjusted to make this into a valid Curve25519 key:
    rawKey.bytes[0] &= 248;
    rawKey.bytes[31] &= 63;
    rawKey.bytes[31] |= 64;
    
    self = [super initWithRawKey: rawKey];
    if (self) {
        RawKey pub;
        crypto_scalarmult_base(pub.bytes, _rawKey.bytes);  // recover public key
        _publicKey = [[PublicKey alloc] initWithRawKey: pub];
    }
    return self;
}


- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (RawNonce)nonce
       forRecipient: (PublicKey*)recipient
{
    NSParameterAssert(recipient != nil);
    size_t msgLen = crypto_box_ZEROBYTES + cleartext.length;
    uint8_t* paddedCleartext = allocPadded(cleartext, crypto_box_ZEROBYTES);
    NSMutableData* ciphertext = [NSMutableData dataWithLength: msgLen];
    crypto_box(ciphertext.mutableBytes, paddedCleartext, msgLen, nonce.bytes,
               recipient.rawKey.bytes, _rawKey.bytes);
    free(paddedCleartext);
    return unpad(ciphertext, crypto_box_BOXZEROBYTES);
}


- (NSData*) decrypt: (NSData*)ciphertext
          withNonce: (RawNonce)nonce
         fromSender: (PublicKey*)sender
{
    NSParameterAssert(sender != nil);
    size_t msgLen = crypto_box_BOXZEROBYTES + ciphertext.length;
    uint8_t* paddedCiphertext = allocPadded(ciphertext, crypto_box_BOXZEROBYTES);
    NSMutableData* cleartext = [NSMutableData dataWithLength: msgLen];
    int result = crypto_box_open(cleartext.mutableBytes, paddedCiphertext, msgLen, nonce.bytes,
                                 sender.rawKey.bytes, _rawKey.bytes);
    free(paddedCiphertext);
    if (result != 0)
        return nil;
    return unpad(cleartext, crypto_box_ZEROBYTES);
}


- (NSData*) sign: (NSData*)input {
    NSParameterAssert(input != nil);
    if (input.length > 256)
        return nil;
    uint8_t signature[64];
    uint8_t random[64];
    SecRandomCopyBytes(kSecRandomDefault, sizeof(random), random);
    if (curve25519_sign(signature, _rawKey.bytes, input.bytes, input.length, random) != 0)
        return nil;
    return [NSData dataWithBytes: signature length: sizeof(signature)];
}


+ (RawNonce) randomNonce {
    RawNonce nonce;
    SecRandomCopyBytes(kSecRandomDefault, sizeof(nonce), nonce.bytes);
    return nonce;
}

+ (void) incrementNonce: (RawNonce*)nonce by: (int8_t)increment {
    for (int pos=sizeof(*nonce)-1; pos >= 0; --pos) {
        int result = (int)nonce->bytes[pos] + increment;
        nonce->bytes[pos] = (uint8_t)result;
        if (result < 0)
            increment = -1;
        else if (result > 255)
            increment = 1;
        else
            break;
    }
}



// mallocs a block with `paddingSize` zero bytes followed by `original`.
static uint8_t* allocPadded(NSData* original, size_t paddingSize) {
    size_t length = original.length;
    uint8_t* padded = malloc(paddingSize + length);
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


@end




@implementation PublicKey

- (BOOL) verifySignature: (NSData*)signature
                  ofData: (NSData*)input
{
    NSParameterAssert(signature != nil);
    NSParameterAssert(input != nil);
    return signature.length == 64
        && curve25519_verify(signature.bytes, _rawKey.bytes, input.bytes, input.length) == 0;
}

@end
