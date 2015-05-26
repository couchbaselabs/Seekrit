//
//  CBKey.m
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//


#import "CBKey.h"
#import "CBKey+Private.h"
#import "sodium.h"
#import "CBSigningKey.h"
#import "CBEncryptingKey.h"
#import <CommonCrypto/CommonKeyDerivation.h>


@implementation CBKey
{
    @protected
    CBRawKey _rawKey;
}


+ (void)initialize {
    if (self == [CBKey class]) {
        sodium_init();
        assert(crypto_box_PUBLICKEYBYTES == sizeof(CBRawKey));
        assert(crypto_box_SECRETKEYBYTES == sizeof(CBRawKey));
        assert(crypto_box_SEEDBYTES == sizeof(CBKeySeed));
        assert(crypto_box_NONCEBYTES == sizeof(CBNonce));
        assert(crypto_sign_PUBLICKEYBYTES == sizeof(CBRawKey));
        assert(crypto_sign_SEEDBYTES == sizeof(CBKeySeed));
        assert(crypto_sign_BYTES == sizeof(CBSignature));
    }
}

+ (instancetype) generate {
    return [[self alloc] init];
}

- (instancetype)init {
    @throw [NSException exceptionWithName: NSInternalInconsistencyException
                                   reason: @"CBKey is abstract" userInfo: nil];
    return [self initWithKeyData: nil];
}

- (instancetype) initWithRawKey: (CBRawKey)rawKey {
    self = [super init];
    if (self) {
        _rawKey = rawKey;
    }
    return self;
}

- (instancetype) initWithKeyData: (NSData*)keyData {
    if (keyData.length != sizeof(CBRawKey))
        return nil;
    return [self initWithRawKey: *(const CBRawKey*)keyData.bytes];
}

- (CBRawKey) rawKey {
    return _rawKey;
}

- (NSData*) keyData {
    return [NSData dataWithBytes: &_rawKey length: sizeof(_rawKey)];
}

- (BOOL) isEqual:(id)object {
    if ([object class] != [self class])
        return NO;
    return memcmp(&_rawKey, &((CBKey*)object)->_rawKey, sizeof(_rawKey)) == 0;
}

- (void) dealloc {
    // Don't leave key data lying around in RAM (remember Heartbleed...)
    memset(&_rawKey, 0, sizeof(_rawKey));
}


#pragma mark - NONCES


+ (CBNonce) randomNonce {
    CBNonce nonce;
    randombytes_buf(nonce.bytes, sizeof(nonce.bytes));
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


@end




@implementation CBPrivateKey


- (instancetype)initWithSeed: (CBKeySeed)seed {
    // By default, treat the seed as a raw key
    return [self initWithRawKey: *(CBRawKey*)&seed];
}


+ (CBPrivateKey*) keyFromPassphrase: (NSString*)passphrase
                             withSalt: (NSData*)salt
                               rounds: (uint32_t)rounds
{
    NSParameterAssert(passphrase);
    NSAssert(salt.length > 4, @"Insufficient salt");
    NSAssert(rounds > 10000, @"Insufficient rounds");
    NSData* passwordData = [passphrase dataUsingEncoding: NSUTF8StringEncoding];
    CBKeySeed seed;
    int status = CCKeyDerivationPBKDF(kCCPBKDF2,
                                      passwordData.bytes, passwordData.length,
                                      salt.bytes, salt.length,
                                      kCCPRFHmacAlgSHA256, rounds,
                                      seed.bytes, sizeof(seed));
    if (status) {
        return nil;
    }
    return [[self alloc] initWithSeed: seed];
}

+ (uint32_t) passphraseRoundsNeededForDelay: (NSTimeInterval)delay
                                   withSalt: (NSData*)salt
{
    return CCCalibratePBKDF(kCCPBKDF2, 10, salt.length, kCCPRFHmacAlgSHA256,
                            sizeof(CBRawKey), (uint32_t)(delay*1000.0));
}


#if TARGET_OS_IPHONE
typedef CFTypeRef SecKeychainRef;
#endif

- (BOOL) addToKeychain: (SecKeychainRef)keychain // parameter is unused in iOS
            forService: (NSString*)service
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

- (BOOL) addToKeychainForService: (NSString*)service
                         account: (NSString*)account
{
    return [self addToKeychain: NULL forService: service account: account];
}


+ (instancetype) keyPairFromKeychain: (SecKeychainRef)keychain
                           forService: (NSString*)service
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


+ (instancetype) keyFromKeychainForService: (NSString*)service
                                        account: (NSString*)account
{
    return [self keyPairFromKeychain: NULL forService: service account: account];
}


@end



@implementation CBPublicKey

- (CBRawKey) rawKey {
    return super.rawKey;
}

- (NSData*) keyData {
    return super.keyData;
}

@end
