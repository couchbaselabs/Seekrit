//
//  CBSymmetricKey.h
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBKey.h"


/** A short identifier sent along with an encrypted message to narrow down the choice of keys. */
typedef UInt16 CBKeyClue;


/** A symmetric key that both encrypts and decrypts.
    Uses the libsodium "crypto_secretbox" API. */
@interface CBSymmetricKey : CBPrivateKey <NSCoding>

/** Encrypts a data block. The encrypted form can only be read using this same key.
    Requires a _nonce_, a 24-byte value that alters the encryption. The nonce can contain anything,
    but it's crucial that no two messages encrypted by this key use the same nonce, otherwise the
    security is weakened.
    Typically the nonce is generated using +randomNonce or +incrementNonce:by:.
    The nonce does not need to be kept secret.
    @param cleartext  The message to be encrypted.
    @param nonce  The nonce (see description above.)
    @return  The encrypted message. */
- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (CBNonce)nonce;

/** Decrypts a data block.
    Requires the _nonce_ value that was used to encrypt the message. (Either the sender needs to
    include the nonce along with the ciphertext, or the parties need to agree on some other way to
    derive it, for example by using a counter of the number of messages sent.)
    @param ciphertext  The encrypted message to be decrypted.
    @param nonce  The nonce that was used to encrypt the message (see above).
    @return  The decrypted message, or nil if it could not be decrypted (because this isn't the
                encrypting key, or the nonce is wrong, or the ciphertext was corrupted.) */
- (NSData*) decrypt: (NSData*)ciphertext
          withNonce: (CBNonce)nonce;

/** Encrypts a data block. The encrypted form can only be read using this same key.
    A random 24-byte nonce is generated and prefixed to the ciphertext. */
- (NSData*) encrypt: (NSData*)cleartext;

/** Decrypts a data block with a prefixed nonce, that was generated by -encrypt:. */
- (NSData*) decrypt: (NSData*)ciphertext;


// CLUES:

/** A 16-bit integer derived from the key data. Knowing this can help identify which key to use
    when decrypting data. (CBKeyBag takes advantage of this.) */
@property (readonly) CBKeyClue clue;

/** Encrypts a data block, prepending the key's 16-bit clue. */
- (NSData*) encryptWithClue: (NSData*)cleartext;

/** Decrypts a data block that's been prepended with a clue. */
- (NSData*) decryptWithClue: (NSData*)ciphertext;

/** Returns the clue prepended to the encrypted data by -encryptWithClue:. */
+ (CBKeyClue) clueForEncryptedData: (NSData*)ciphertext;

@end
