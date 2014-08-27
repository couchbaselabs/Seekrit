//
//  Key.m
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

// http://cr.yp.to/ecdh.html
// http://ed25519.cr.yp.to
// http://nacl.cr.yp.to/box.html


#import "Key.h"
#import "tweetnacl.h"
#import "curve_sigs.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>


// External function called by tweetnacl.c
void randombytes(uint8_t* bytes, uint64_t count) {
    SecRandomCopyBytes(kSecRandomDefault, (size_t)count, bytes);
}


typedef struct {
    uint8_t bytes[32];
} SHA256Digest;




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

+ (PrivateKey*) keyPairFromPassphrase: (NSString*)passphrase
                             withSalt: (NSData*)salt
                               rounds: (uint32_t)rounds
{
    NSParameterAssert(passphrase);
    NSAssert(salt.length > 4, @"Insufficient salt");
    NSAssert(rounds > 10000, @"Insufficient rounds");
    NSData* passwordData = [passphrase dataUsingEncoding: NSUTF8StringEncoding];
    RawKey priv;
    int status = CCKeyDerivationPBKDF(kCCPBKDF2,
                                      passwordData.bytes, passwordData.length,
                                      salt.bytes, salt.length,
                                      kCCPRFHmacAlgSHA256, rounds,
                                      priv.bytes, sizeof(priv));
    if (status) {
        return nil;
    }
    return [[PrivateKey alloc] initWithRawKey: priv];
}

+ (uint32_t) passphraseRoundsNeededForDelay: (NSTimeInterval)delay
                                   withSalt: (NSData*)salt
{
    return CCCalibratePBKDF(kCCPBKDF2, 10, salt.length, kCCPRFHmacAlgSHA256,
                            sizeof(RawKey), (uint32_t)(delay*1000.0));
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

- (void) dealloc {
    // Don't leave key data lying around in RAM (remember Heartbleed...)
    memset(&_rawKey, 0, sizeof(_rawKey));
}


@end




@implementation PrivateKey


@synthesize publicKey=_publicKey;


- (instancetype)initWithRawKey:(RawKey)rawKey {
    // A few bits need to be adjusted to make this into a valid Curve25519 key:
    rawKey.bytes[ 0] &= 0xF8;
    rawKey.bytes[31] &= 0x3F;
    rawKey.bytes[31] |= 0x40;
    
    self = [super initWithRawKey: rawKey];
    if (self) {
        RawKey pub;
        crypto_scalarmult_base(pub.bytes, _rawKey.bytes);  // recover public key
        _publicKey = [[PublicKey alloc] initWithRawKey: pub];
    }
    return self;
}


- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (Nonce)nonce
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
          withNonce: (Nonce)nonce
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


- (Signature) signDigest: (const void*)digest
                     length: (size_t)length
{
    NSParameterAssert(digest != NULL);
    NSParameterAssert(length <= 256);
    Signature signature;
    uint8_t random[64];
    SecRandomCopyBytes(kSecRandomDefault, sizeof(random), random);
    if (curve25519_sign(signature.bytes, _rawKey.bytes, digest, length, random) != 0) {
        [NSException raise: NSInternalInconsistencyException
                    format: @"Curve25519 signing failed"];
    }
    return signature;
}

- (Signature) sign: (NSData*)input {
    SHA256Digest digest;
    CC_SHA256(input.bytes, (CC_LONG)input.length, digest.bytes);
    return [self signDigest: digest.bytes length: sizeof(digest)];
}


+ (Nonce) randomNonce {
    Nonce nonce;
    SecRandomCopyBytes(kSecRandomDefault, sizeof(nonce), nonce.bytes);
    return nonce;
}

+ (void) incrementNonce: (Nonce*)nonce by: (int8_t)increment {
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

- (BOOL) verifySignature: (Signature)signature
                ofDigest: (const void*)digest
                  length: (size_t)length
{
    NSParameterAssert(digest != nil);
    NSParameterAssert(length <= 256);
    return curve25519_verify(signature.bytes, _rawKey.bytes, digest, length) == 0;
}

- (BOOL) verifySignature: (Signature)signature
                  ofData: (NSData*)input
{
    SHA256Digest digest;
    CC_SHA256(input.bytes, (CC_LONG)input.length, digest.bytes);
    return [self verifySignature: signature ofDigest: digest.bytes length: sizeof(digest)];
}


@end
