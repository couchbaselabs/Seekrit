//
//  CBEncryptingKey.h
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBKey.h"
@class CBEncryptingPublicKey;


/** A Curve25519 private key used to encrypt and decrypt messages.
    Uses the libsodium "crypto_box" API. */
@interface CBEncryptingPrivateKey : CBPrivateKey

/** The corresponding public key. */
@property CBEncryptingPublicKey* publicKey;

/** Encrypts a data block. The encrypted form can only be read using the recipient's private key.
    Requires a _nonce_, a 24-byte value that alters the encryption. The nonce can contain anything,
    but it's crucial that no two messages exchanged by this key-pair and the recipient (in either
    direction) use the same nonce, otherwise the security is weakened.
    Typically the nonce is generated using +randomNonce or +incrementNonce:by:.
    The nonce does not need to be kept secret.
    @param cleartext  The message to be encrypted.
    @param nonce  A 24-byte value that alters the encryption (see description.)
    @param recipient  The public key of the recipient. Only the corresponding private key can be
                used to decrypt the message.
    @return  The encrypted message. */
- (NSData*) encrypt: (NSData*)cleartext
          withNonce: (CBNonce)nonce
       forRecipient: (CBEncryptingPublicKey*)recipient;

/** Encrypts a data block, appending the result to an existing NSMutableData.
    For details, see -encrypt:withNonce:forRecipient:. */
- (void) encrypt: (NSData*)cleartext
       withNonce: (CBNonce)nonce
    forRecipient: (CBEncryptingPublicKey*)recipient
        appendTo: (NSMutableData*)output;

/** Decrypts a data block.
    Requires the _nonce_ value that was used to encrypt the message. (Either the sender needs to
    include the nonce along with the ciphertext, or the parties need to agree on some other way to
    derive it, for example by using a counter of the number of messages sent.)
    @param ciphertext  The encrypted message to be decrypted.
    @param nonce  The nonce that was used to encrypt the message (see above).
    @param sender  The public key of the sender.
    @return  The decrypted message, or nil if it could not be decrypted (because this isn't the
                intended recipient's private key, or the nonce is wrong, or the sender key doesn't
                match, or the ciphertext was corrupted.) */
- (NSData*) decrypt: (NSData*)ciphertext
          withNonce: (CBNonce)nonce
         fromSender: (CBEncryptingPublicKey*)sender;

@end



/** A public key used to encrypt messages addressed to the owner of its private key.
    Only the matching private key can be used to decrypt such messages. */
@interface CBEncryptingPublicKey : CBPublicKey
@end