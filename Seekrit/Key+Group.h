//
//  Key+Group.h
//  Seekrit
//
//  Created by Jens Alfke on 8/27/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import "Key.h"


@interface PrivateKey (GroupEncryption)

/** Encrypts a message so that any of the recipients can decipher it.
    @param cleartext  The message to be encrypted.
    @param recipients  An array of PublicKey objects corresponding to the recipients who should be
                    able to decipher the message.
    @return  The encrypted data. */
- (NSData*) encryptGroupMessage: (NSData*)cleartext
                  forRecipients: (NSArray*)recipients;

/** Decrypts a message encrypted by -encryptGroupMessage:forRecipients:.
    This PrivateKey must correspond to one of the public keys given as a recipient when the message
    was encrypted. */
- (NSData*) decryptGroupMessage: (NSData*)ciphertext
                     fromSender: (PublicKey*)sender;

@end
