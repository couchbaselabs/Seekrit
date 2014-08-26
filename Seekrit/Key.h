//
//  Key.h
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
@class PrivateKey, PublicKey;


/** The raw bytes of a Curve25519 key. */
typedef struct {
    uint8_t bytes[32];
} RawKey;

/** The raw bytes of a nonce used for encryption. */
typedef struct {
    uint8_t bytes[24];
} RawNonce;



/** Abstract superclass of PublicKey and PrivateKey. */
@interface Key : NSObject

/** Generates a new PrivateKey/PublicKey pair at random. */
+ (PrivateKey*) generateKeyPair;

/** Reconstitutes a Key object from previously saved raw key data.
    A PrivateKey also reconstitutes its PublicKey.
    Note: This method can be used to create a key pair from any combination of 32 bytes.
    It can thus be used to derive a key-pair from a passphrase. */
- (instancetype) initWithRawKey: (RawKey)rawKey;

/** Reconstitutes a key from previously saved data in the form of NSData.
    (See -initWithRawKey: for details.)*/
- (instancetype) initWithKeyData: (NSData*)keyData;

/** The key's raw bytes as an NSData object. */
@property (readonly) NSData* keyData;

/** The key's raw bytes as a C struct. */
@property (readonly) RawKey rawKey;

@end



/** A Curve25519 private key. */
@interface PrivateKey : Key

/** The matching PublicKey to this PrivateKey. */
@property PublicKey* publicKey;

/** Encrypts a data block. The encrypted form can only be read using the recipient's private key.
    @param cleartext  The message to be encrypted.
    @param nonce  A 24-byte value that alters the encryption. It can contain anything, but it's
                important that no two messages exchanged by this key-pair and the recipient (in
                either direction) use the same nonce, otherwise the security is weakened.
    @param recipient  The public key of the recipient. Only the corresponding private key can be
                used to decrypt the message.
    @return  The encrypted message. */
- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (RawNonce)nonce
       forRecipient: (PublicKey*)recipient;

/** Decrypts a data block.
    @param ciphertext  The encrypted message to be decrypted.
    @param nonce  A 24-byte value that alters the encryption. This must be the same nonce value
                that was used to encrypt the message. (Either the sender needs to include the
                nonce along with the ciphertext, or they need to agree on some other way to
                derive it, for example by using a counter of the number of message sent.)
    @param recipient  The public key of the sender.
    @return  The decrypted message, or nil if it could not be decrypted (because this isn't the
                intended recipient's private key, or the nonce is wrong, or the sender key doesn't
                match, or the ciphertext was corrupted.) */
- (NSData*) decrypt: (NSData*)ciphertext
          withNonce: (RawNonce)nonce
         fromSender: (PublicKey*)sender;

/** Creates a digital signature of a block of data.
    The matching public key can later be used to verify the signature.
    @param input  The data to be signed. Must be no more than 256 bytes long.
    @return  The signature (which will be 64 bytes long.) */
- (NSData*) sign: (NSData*)input;

/** Generates a random nonce for use when encrypting. */
+ (RawNonce) randomNonce;

/** Increments (or decrements) a nonce, treating it as a 192-bit big-endian integer. */
+ (void) incrementNonce: (RawNonce*)nonce by: (int8_t)increment;

@end



/** A Curve25519 public key. */
@interface PublicKey : Key

/** Verifies a digital signature using this public key.
    @param signature  The signature to be verified.
    @param input  The data whose signature is to be verified.
    @return  YES if the signature was created from this input data by the corresponding private
                key; NO if the signature is invalid or doesn't match. */
- (BOOL) verifySignature: (NSData*)signature
                  ofData: (NSData*)input;

@end
