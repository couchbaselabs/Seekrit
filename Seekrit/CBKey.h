//
//  CBKey.h
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>


/** The raw data of a Curve25519 or Ed25519 key. (256 bits, 32 bytes) */
typedef struct {
    uint8_t bytes[32];
} CBRawKey;

/** A nonce used for Curve25519 encryption. (192 bits, 24 bytes) */
typedef struct {
    uint8_t bytes[24];
} CBNonce;



/** A Curve25519 or Ed25519 key; abstract superclass of CBPublicKey and CBPrivateKey. */
@interface CBKey : NSObject

/** Generates a new key (or key-pair) at random. Same as -init. */
+ (instancetype) generate;

/** Reconstitutes a Key object from previously saved raw key data.
    A CBPrivateKey also reconstitutes its CBPublicKey. */
- (instancetype) initWithRawKey: (CBRawKey)rawKey NS_DESIGNATED_INITIALIZER;

/** Reconstitutes a key from previously saved data in the form of NSData. */
- (instancetype) initWithKeyData: (NSData*)keyData;

//////// NONCE UTILITIES:

/** Generates a random nonce for use when encrypting. */
+ (CBNonce) randomNonce;

/** Increments (or decrements) a nonce, treating it as a 192-bit big-endian integer. */
+ (void) incrementNonce: (CBNonce*)nonce by: (int8_t)increment;

@end



/** A key whose contents are sensitive, i.e. a symmetric key, or the private key of a key-pair.
    Note that private keys (other than symmetric keys) don't provide access to their raw data.
    This is intentional. Such keys should only be stored in the Keychain. */
@interface CBPrivateKey : CBKey

/** Creates a private key (and any matching public key) derived from a password using PBKDF2.
    The same input values will always create the same keys. In practice, the `salt` and `rounds`
    parameters should be fixed (hardcoded in the app) while the passphrase should be entered by
    the user.
    @param passphrase  The passphrase/password, presumably entered by the user.
    @param salt  A data blob that perturbs the generated key; must be at least 4 bytes long.
                Should usually be kept fixed for any particular app, but doesn't need to be secret.
    @param rounds  The number of rounds of hashing to perform. More rounds is more secure but takes
                longer. */
+ (instancetype) keyFromPassphrase: (NSString*)passphrase
                          withSalt: (NSData*)salt
                            rounds: (uint32_t)rounds;

/** Estimates the number of rounds needed to make +keyPairFromPassphrase: take a given amount of time
    on the current CPU. The goal is to make it take a macroscopic amount of time (like a second) 
    in order to make password cracking impractical, but not long enough to annoy the user. */
+ (uint32_t) passphraseRoundsNeededForDelay: (NSTimeInterval)delay
                                   withSalt: (NSData*)salt;

//////// KEYCHAIN:

/** Reads a private key (and any public key) from the Keychain, looking up the given service and
    account. */
+ (instancetype) keyFromKeychainForService: (NSString*)service
                                   account: (NSString*)account;

/** Adds a private key to the Keychain under the given service and account names. */
- (BOOL) addToKeychainForService: (NSString*)service
                         account: (NSString*)account
                           error: (NSError**)outError;

#if !TARGET_OS_IPHONE // OS X only; iOS doesn't support multiple Keychains.
/** Adds a private key to a specific Keychain under the given service and account names. */
- (BOOL) addToKeychain: (SecKeychainRef)keychain
            forService: (NSString*)service
               account: (NSString*)account
                 error: (NSError**)outError;

/** Reads a private key (and its public key) from a specific Keychain, looking up the given service
    and account. */
+ (instancetype) keyPairFromKeychain: (SecKeychainRef)keychain
                           forService: (NSString*)service
                              account: (NSString*)account;
#endif

@end



/** Abstract public-key class that goes along with CBPrivateKey. */
@interface CBPublicKey : CBKey

/** The key's raw bytes as an NSData object. */
@property (readonly) NSData* keyData;

/** The key's raw bytes as a C struct. */
@property (readonly) CBRawKey rawKey;

@end
