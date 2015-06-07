//
//  CBKey+Group.h
//  Seekrit
//
//  Created by Jens Alfke on 8/27/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import "CBEncryptingPrivateKey.h"


@interface CBEncryptingPrivateKey (GroupEncryption)

/** Encrypts a message so that any of the recipients can decipher it.
    @param cleartext  The message to be encrypted.
    @param recipientPublicKeys  An array of CBEncryptingPublicKey objects corresponding to the
            recipients who should be able to decipher the message.
    @return  The encrypted data. */
- (NSData*) encryptGroupMessage: (NSData*)cleartext
                  forRecipients: (NSArray*)recipientPublicKeys;

/** Decrypts a message encrypted by -encryptGroupMessage:forRecipients:.
    This PrivateKey must correspond to one of the public keys given as a recipient when the message
    was encrypted. */
- (NSData*) decryptGroupMessage: (NSData*)ciphertext
                     fromSender: (CBEncryptingPublicKey*)sender;

@end
