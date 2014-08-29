//
//  CBKey.h
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
@class CBPrivateKey, CBPublicKey;


#if TARGET_OS_IPHONE
typedef CFTypeRef CBKeychainRef;
#else
typedef SecKeychainRef CBKeychainRef;
#endif


/** The raw bytes of a Curve25519 key. */
typedef struct {
    uint8_t bytes[32];
} CBRawKey;

/** A nonce used for Curve25519 encryption. */
typedef struct {
    uint8_t bytes[24];
} CBNonce;

/** A Curve25519 digital signature. */
typedef struct {
    uint8_t bytes[64];
} CBSignature;


/** A Curve25519 key; abstract superclass of PublicKey and PrivateKey. */
@interface CBKey : NSObject

/** Reconstitutes a Key object from previously saved raw key data.
    A PrivateKey also reconstitutes its PublicKey. */
- (instancetype) initWithRawKey: (CBRawKey)rawKey;

/** Reconstitutes a key from previously saved data in the form of NSData.
    (See -initWithRawKey: for details.)*/
- (instancetype) initWithKeyData: (NSData*)keyData;

/** The key's raw bytes as an NSData object. */
@property (readonly) NSData* keyData;

/** The key's raw bytes as a C struct. */
@property (readonly) CBRawKey rawKey;

@end



/** A Curve25519 private key. */
@interface CBPrivateKey : CBKey

/** The matching PublicKey to this PrivateKey. */
@property CBPublicKey* publicKey;

/** Generates a new PrivateKey/PublicKey pair at random. */
+ (CBPrivateKey*) generateKeyPair;

/** Creates a PrivateKey/PublicKey pair, derived from a password using PBKDF2.
    The same input values will always create the same key pair. In practice, the salt and rounds
    parameters should be fixed (hardcoded in the app) while the passphrase should be entered by the
    user.
    @param passphrase  The passphrase/password, presumably entered by the user.
    @param salt  A data blob that perturbs the generated key; must be at least 4 bytes long.
                Should usually be kept fixed for any particular app, but doesn't need to be secret.
    @param rounds  The number of rounds of hashing to perform. More rounds is more secure but takes
                longer. */
+ (CBPrivateKey*) keyPairFromPassphrase: (NSString*)passphrase
                               withSalt: (NSData*)salt
                                 rounds: (uint32_t)rounds;

/** Estimates the number of rounds needed to make +keyPairFromPassphrase: take a given amount of time
    on the current CPU. The goal is to make it take a macroscopic amount of time (like a second) 
    in order to make password cracking impractical, but not long enough to annoy the user. */
+ (uint32_t) passphraseRoundsNeededForDelay: (NSTimeInterval)delay
                                   withSalt: (NSData*)salt;


/** Reads a private key (and its public key) from the Keychain, looking up the given service and
    account. */
+ (CBPrivateKey*) keyPairFromKeychain: (CBKeychainRef)keychain
                          withService: (NSString*)service
                              account: (NSString*)account;

/** Adds a private key to the Keychain under the given service and account names. */
- (BOOL) addToKeychain: (CBKeychainRef)keychain
           withService: (NSString*)service
               account: (NSString*)account;

/** Encrypts a data block. The encrypted form can only be read using the recipient's private key.
    @param cleartext  The message to be encrypted.
    @param nonce  A 24-byte value that alters the encryption. It can contain anything, but it's
                important that no two messages exchanged by this key-pair and the recipient (in
                either direction) use the same nonce, otherwise the security is weakened.
    @param recipient  The public key of the recipient. Only the corresponding private key can be
                used to decrypt the message.
    @return  The encrypted message. */
- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (CBNonce)nonce
       forRecipient: (CBPublicKey*)recipient;

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
          withNonce: (CBNonce)nonce
         fromSender: (CBPublicKey*)sender;

//////// SIGNATURES:

/** Creates a digital signature of a block of data, using this key.
    (Actually it uses the closely related Ed25519 key.)
    The matching public key can later be used to verify the signature.
    @param input  The data to be signed.
    @return  The signature (which will be 64 bytes long.) */
- (CBSignature) sign: (NSData*)input;

/** Lower-level signature method that can only sign up to 256 bytes.
    You can use this if you've computed your own cryptographic digest of the data.
    (The regular -sign: method uses this to sign a 32-byte SHA256 digest.) */
- (CBSignature) signDigest: (const void*)digest
                    length: (size_t)length;

//////// NONCE UTILITIES:

/** Generates a random nonce for use when encrypting. */
+ (CBNonce) randomNonce;

/** Increments (or decrements) a nonce, treating it as a 192-bit big-endian integer. */
+ (void) incrementNonce: (CBNonce*)nonce by: (int8_t)increment;

@end



/** A Curve25519 public key. */
@interface CBPublicKey : CBKey

/** Verifies a digital signature using this public key.
    (Actually it uses the closely related Ed25519 key.)
    @param signature  The signature to be verified.
    @param input  The data whose signature is to be verified.
    @return  YES if the signature was created from this input data by the corresponding private
                key; NO if the signature is invalid or doesn't match. */
- (BOOL) verifySignature: (CBSignature)signature
                  ofData: (NSData*)input;

/** Lower-level signature verification that can only handle 256 bytes.
    You can use this if you've computed your own cryptographic digest of the data.
    (The regular -verifySignature:ofData: method uses this to verify a SHA256 digest.) */
- (BOOL) verifySignature: (CBSignature)signature
                ofDigest: (const void*)digest
                  length: (size_t)length;

@end
