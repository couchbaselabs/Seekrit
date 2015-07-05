//
//  CBSymmetricKey.m
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBSymmetricKey.h"
#import "CBKey+Private.h"
#import "sodium.h"


@implementation CBSymmetricKey

@synthesize keyData=_keyData;


- (instancetype)init {
    CBRawKey rawKey;
    randombytes_buf(rawKey.bytes, sizeof(rawKey.bytes));
    return [super initWithRawKey: rawKey];
}


- (instancetype) initWithCoder:(NSCoder *)decoder {
    NSUInteger length;
    const void* raw = [decoder decodeBytesForKey: @"key" returnedLength: &length];
    if (!raw || length != sizeof(CBRawKey))
        return nil;
    return [self initWithRawKey: *(CBRawKey*)raw];
}


- (void) encodeWithCoder:(NSCoder *)encoder {
    CBRawKey rawKey = self.rawKey;
    [encoder encodeBytes: (const uint8_t*)&rawKey length: sizeof(rawKey) forKey: @"key"];
}


- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (CBNonce)nonce
{
    size_t clearLen = cleartext.length;
    size_t cipherLen = clearLen + crypto_secretbox_MACBYTES;
    void* ciphertext = malloc(cipherLen);
    crypto_secretbox_easy(ciphertext, cleartext.bytes, clearLen, nonce.bytes, self.rawKey.bytes);
    return [NSData dataWithBytesNoCopy: ciphertext length: cipherLen freeWhenDone: YES];
}


- (NSData*) decrypt: (NSData*)ciphertext
          withNonce: (CBNonce)nonce
{
    NSParameterAssert(ciphertext != nil);

    if (ciphertext.length < crypto_secretbox_MACBYTES)
        return nil;
    size_t msgLen = ciphertext.length - crypto_secretbox_MACBYTES;
    NSMutableData* cleartext = [NSMutableData dataWithLength: msgLen];
    if (0 != crypto_secretbox_open_easy(cleartext.mutableBytes,
                                        ciphertext.bytes, ciphertext.length,
                                        nonce.bytes, self.rawKey.bytes))
        return nil;
    return cleartext;
}


- (NSData*) encrypt: (NSData*)cleartext {
    size_t clearLen = cleartext.length;
    size_t cipherLen = clearLen + crypto_secretbox_MACBYTES;
    size_t outputLen = cipherLen + sizeof(CBNonce);
    void* ciphertext = malloc(outputLen);
    // Encrypted data is prefixed with the nonce
    CBNonce *nonce = ciphertext;
    *nonce = [CBKey randomNonce];
    crypto_secretbox_easy(ciphertext + sizeof(CBNonce), cleartext.bytes, clearLen,
                          nonce->bytes, self.rawKey.bytes);
    return [NSData dataWithBytesNoCopy: ciphertext length: outputLen freeWhenDone: YES];
}


- (NSData*) decrypt: (NSData*)ciphertext {
    NSParameterAssert(ciphertext != nil);

    if (ciphertext.length < crypto_secretbox_MACBYTES + sizeof(CBNonce))
        return nil;
    const CBNonce *nonce = ciphertext.bytes;    // Recover the nonce used to encrypt

    size_t cipherLen = ciphertext.length - sizeof(CBNonce);
    size_t msgLen = cipherLen - crypto_secretbox_MACBYTES;
    NSMutableData* cleartext = [NSMutableData dataWithLength: msgLen];
    if (0 != crypto_secretbox_open_easy(cleartext.mutableBytes,
                                        ciphertext.bytes + sizeof(CBNonce), cipherLen,
                                        nonce->bytes, self.rawKey.bytes))
        return nil;
    return cleartext;
}


#pragma mark - CLUES:


- (CBKeyClue) clue {
    CBRawKey rawKey = self.rawKey;
    // DJB2 hash function:
    uint32_t hash = 5381;
    for (int i = 0; i < sizeof(rawKey.bytes); ++i)
        hash = ((hash << 5) + hash) + rawKey.bytes[i];
    return (UInt16)hash;
}


- (NSData*) encryptWithClue: (NSData*)cleartext {
    CBKeyClue clue = NSSwapHostShortToBig(self.clue);
    NSMutableData* ciphertext = [[self encrypt: cleartext] mutableCopy];
    [ciphertext replaceBytesInRange: NSMakeRange(0, 0) withBytes: &clue length: sizeof(clue)];
    return ciphertext;
}


- (NSData*) decryptWithClue: (NSData*)ciphertext {
    if (ciphertext.length < 2)
        return nil;
    if ([[self class] clueForEncryptedData: ciphertext] != self.clue)
        return nil;
    return [self decrypt: [ciphertext subdataWithRange: NSMakeRange(2, ciphertext.length-2)]];
}


+ (CBKeyClue) clueForEncryptedData: (NSData*)ciphertext {
    return NSSwapBigShortToHost(*(CBKeyClue*)ciphertext.bytes);
}


@end
