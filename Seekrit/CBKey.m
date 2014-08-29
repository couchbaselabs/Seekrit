//
//  CBKey.m
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

// http://cr.yp.to/ecdh.html
// http://ed25519.cr.yp.to
// http://nacl.cr.yp.to/box.html


#import "CBKey.h"
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




@implementation CBKey
{
    @protected
    CBRawKey _rawKey;
}

@synthesize rawKey=_rawKey;

- (instancetype) initWithRawKey: (CBRawKey)rawKey {
    self = [super init];
    if (self) {
        _rawKey = rawKey;
    }
    return self;
}

- (instancetype) initWithKeyData: (NSData*)keyData
{
    if (keyData.length != sizeof(CBRawKey))
        return nil;
    return [self initWithRawKey: *(const CBRawKey*)keyData.bytes];
}

- (NSData*) keyData {
    return [NSData dataWithBytes: &_rawKey length: sizeof(_rawKey)];
}

- (BOOL) isEqual:(id)object {
    if (![object isKindOfClass: [CBKey class]])
        return NO;
    return memcmp(&_rawKey, &((CBKey*)object)->_rawKey, sizeof(_rawKey)) == 0;
}

- (void) dealloc {
    // Don't leave key data lying around in RAM (remember Heartbleed...)
    memset(&_rawKey, 0, sizeof(_rawKey));
}


@end




@implementation CBPrivateKey


@synthesize publicKey=_publicKey;


+ (CBPrivateKey*) generateKeyPair {
    CBRawKey priv;
    SecRandomCopyBytes(kSecRandomDefault, sizeof(priv), priv.bytes);
    return [[CBPrivateKey alloc] initWithRawKey: priv];
}


+ (CBPrivateKey*) keyPairFromPassphrase: (NSString*)passphrase
                             withSalt: (NSData*)salt
                               rounds: (uint32_t)rounds
{
    NSParameterAssert(passphrase);
    NSAssert(salt.length > 4, @"Insufficient salt");
    NSAssert(rounds > 10000, @"Insufficient rounds");
    NSData* passwordData = [passphrase dataUsingEncoding: NSUTF8StringEncoding];
    CBRawKey priv;
    int status = CCKeyDerivationPBKDF(kCCPBKDF2,
                                      passwordData.bytes, passwordData.length,
                                      salt.bytes, salt.length,
                                      kCCPRFHmacAlgSHA256, rounds,
                                      priv.bytes, sizeof(priv));
    if (status) {
        return nil;
    }
    return [[CBPrivateKey alloc] initWithRawKey: priv];
}

+ (uint32_t) passphraseRoundsNeededForDelay: (NSTimeInterval)delay
                                   withSalt: (NSData*)salt
{
    return CCCalibratePBKDF(kCCPBKDF2, 10, salt.length, kCCPRFHmacAlgSHA256,
                            sizeof(CBRawKey), (uint32_t)(delay*1000.0));
}


- (instancetype)initWithRawKey:(CBRawKey)rawKey {
    // A few bits need to be adjusted to make this into a valid Curve25519 key:
    rawKey.bytes[ 0] &= 0xF8;
    rawKey.bytes[31] &= 0x3F;
    rawKey.bytes[31] |= 0x40;
    
    self = [super initWithRawKey: rawKey];
    if (self) {
        CBRawKey pub;
        crypto_scalarmult_base(pub.bytes, _rawKey.bytes);  // recover public key
        _publicKey = [[CBPublicKey alloc] initWithRawKey: pub];
    }
    return self;
}


- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (CBNonce)nonce
       forRecipient: (CBPublicKey*)recipient
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
          withNonce: (CBNonce)nonce
         fromSender: (CBPublicKey*)sender
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


- (CBSignature) signDigest: (const void*)digest
                     length: (size_t)length
{
    NSParameterAssert(digest != NULL);
    NSParameterAssert(length <= 256);
    CBSignature signature;
    uint8_t random[64];
    SecRandomCopyBytes(kSecRandomDefault, sizeof(random), random);
    if (curve25519_sign(signature.bytes, _rawKey.bytes, digest, length, random) != 0) {
        [NSException raise: NSInternalInconsistencyException
                    format: @"Curve25519 signing failed"];
    }
    return signature;
}

- (CBSignature) sign: (NSData*)input {
    SHA256Digest digest;
    CC_SHA256(input.bytes, (CC_LONG)input.length, digest.bytes);
    return [self signDigest: digest.bytes length: sizeof(digest)];
}


- (BOOL) addToKeychain: (CBKeychainRef)keychain
           withService: (NSString*)service
               account: (NSString*)account
{
    NSData* itemData = [self.keyData base64EncodedDataWithOptions: 0];
    NSDate* now = [NSDate date];
    NSDictionary* attrs = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                             (__bridge id)kSecAttrService: service,
                             (__bridge id)kSecAttrAccount: account,
                             (__bridge id)kSecValueData: itemData,
                             (__bridge id)kSecAttrCreationDate: now,
                             (__bridge id)kSecAttrModificationDate: now,
                             (__bridge id)kSecAttrDescription: @"curve25519 private key",
                             };
#if !TARGET_OS_IPHONE
    if (keychain) {
        NSMutableDictionary* attrs2 = [attrs mutableCopy];
        attrs2[(__bridge id)kSecUseKeychain] = (__bridge id)keychain;
        attrs = attrs2;
    }
#endif
    CFTypeRef result = NULL;
    OSStatus err = SecItemAdd((__bridge CFDictionaryRef)attrs, &result);
    return err == noErr;
}


+ (CBPrivateKey*) keyPairFromKeychain: (CBKeychainRef)keychain
                          withService: (NSString*)service
                              account: (NSString*)account
{
    NSDictionary* attrs = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                             (__bridge id)kSecAttrService: service,
                             (__bridge id)kSecAttrAccount: account,
                             (__bridge id)kSecReturnData: @YES,
                             };
#if !TARGET_OS_IPHONE
    if (keychain) {
        NSMutableDictionary* attrs2 = [attrs mutableCopy];
        attrs2[(__bridge id)kSecMatchSearchList] = @[(__bridge id)keychain];
        attrs = attrs2;
    }
#endif
    CFTypeRef result = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)attrs, &result);
    if (err || result == NULL) {
        return nil;
    }
    NSData* itemData = CFBridgingRelease(result);
    NSData* keyData = [[NSData alloc] initWithBase64EncodedData: itemData options: 0];
    if (!keyData)
        return nil;
    return [[self alloc] initWithKeyData: keyData];
}


+ (CBNonce) randomNonce {
    CBNonce nonce;
    SecRandomCopyBytes(kSecRandomDefault, sizeof(nonce), nonce.bytes);
    return nonce;
}

+ (void) incrementNonce: (CBNonce*)nonce by: (int8_t)increment {
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




@implementation CBPublicKey

- (BOOL) verifySignature: (CBSignature)signature
                ofDigest: (const void*)digest
                  length: (size_t)length
{
    NSParameterAssert(digest != nil);
    NSParameterAssert(length <= 256);
    return curve25519_verify(signature.bytes, _rawKey.bytes, digest, length) == 0;
}

- (BOOL) verifySignature: (CBSignature)signature
                  ofData: (NSData*)input
{
    SHA256Digest digest;
    CC_SHA256(input.bytes, (CC_LONG)input.length, digest.bytes);
    return [self verifySignature: signature ofDigest: digest.bytes length: sizeof(digest)];
}


@end
