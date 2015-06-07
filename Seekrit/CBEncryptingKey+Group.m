//
//  CBKey+Group.m
//  Seekrit
//
//  Created by Jens Alfke on 8/27/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import "CBEncryptingKey+Group.h"
#import "CBKey+Private.h"
#import "sodium.h"


/*
 Data format:
    Nonce                       24 bytes
    Recipient count              4 bytes
    for each recipient {
        encrypted session key   32 bytes + 16 bytes overhead
    }
    cleartext encrypted with session key (16 bytes overhead)
 */

#define kCBEncryptedMessageOverhead crypto_box_MACBYTES

typedef struct {
    uint8_t bytes[ sizeof(CBRawKey) + kCBEncryptedMessageOverhead ];
} GroupMessageEncryptedKey;

typedef struct {
    CBNonce nonce;
    uint32_t count;
    GroupMessageEncryptedKey encryptedKey[0]; // variable length
} GroupMessage;


@implementation CBEncryptingPrivateKey (GroupEncryption)

- (NSData*) encryptGroupMessage: (NSData*)cleartext
                  forRecipients: (NSArray*)recipients
{
    NSMutableData* output = [NSMutableData dataWithCapacity: sizeof(GroupMessage)
                                            + recipients.count * sizeof(GroupMessageEncryptedKey)
                                            + cleartext.length + kCBEncryptedMessageOverhead];
    // Generate a random nonce and write it:
    CBNonce nonce = [CBEncryptingPrivateKey randomNonce];
    [output appendBytes: &nonce length: sizeof(nonce)];

    // Generate a random session key-pair:
    CBEncryptingPrivateKey* sessionKey = [CBEncryptingPrivateKey generate];
    NSData* sessionPrivateKeyData = sessionKey.keyData;

    // Write the recipient count, and the session's private key encrypted for each recipient:
    uint32_t bigCount = CFSwapInt32HostToBig((uint32_t)recipients.count);
    [output appendBytes: &bigCount length: sizeof(bigCount)];
    for (CBEncryptingPublicKey* recipient in recipients) {
        // (It's OK to reuse the same nonce, because each recipient public key is different)
        [self encrypt: sessionPrivateKeyData
            withNonce: nonce
         forRecipient: recipient
             appendTo: output];
    }

    // Finally append the ciphertext, encrypted with me as sender and session key as recipient:
    [self encrypt: cleartext
        withNonce: nonce
     forRecipient: sessionKey.publicKey
         appendTo: output];
    return output;
}


- (NSData*) decryptGroupMessage: (NSData*)input
                     fromSender: (CBEncryptingPublicKey*)sender
{
    // Read the header:
    size_t inputLen = input.length;
    if (inputLen < sizeof(GroupMessage))
        return nil;
    const GroupMessage* header = input.bytes;
    uint32_t count = CFSwapInt32BigToHost(header->count);
    if (inputLen < offsetof(GroupMessage, encryptedKey[count]))
        return nil;
    // Look at each recipient's encrypted session key looking for one I can decrypt:
    NSData* sessionKeyData = nil;
    for (uint32_t i = 0; i < count; i++) {
        NSData* item = [[NSData alloc] initWithBytesNoCopy: (void*)&header->encryptedKey[i]
                                                    length: sizeof(header->encryptedKey[i])
                                              freeWhenDone: NO];
        sessionKeyData = [self decrypt: item withNonce: header->nonce fromSender: sender];
        if (sessionKeyData)
            break;
    }
    if (!sessionKeyData)
        return nil; // Apparently it wasn't addressed to me :(

    CBEncryptingPrivateKey* sessionKey = [[CBEncryptingPrivateKey alloc] initWithKeyData: sessionKeyData];
    if (!sessionKey)
        return nil;

    // Decrypt the ciphertext, which was encrypted with the session key as recipient:
    NSData* ciphertext = [[NSData alloc] initWithBytesNoCopy: (void*)&header->encryptedKey[count]
                                              length: input.length - offsetof(GroupMessage,
                                                                              encryptedKey[count])
                                        freeWhenDone: NO];
    return [sessionKey decrypt: ciphertext withNonce: header->nonce fromSender: sender];
}


@end
