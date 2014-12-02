//
//  CBKey+Group.m
//  Seekrit
//
//  Created by Jens Alfke on 8/27/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import "CBKey+Group.h"


/*
 Data format:
    Nonce                       24 bytes
    Recipient count              4 bytes
    for each recipient {
        encrypted session key   32 bytes + 16 bytes overhead
    }
    cleartext encrypted with session key (16 bytes overhead)
 */

#define kCBEncryptedMessageOverhead 16

typedef struct {
    uint8_t bytes[ sizeof(CBRawKey) + kCBEncryptedMessageOverhead ];
} GroupMessageEncryptedKey;

typedef struct {
    CBNonce nonce;
    uint32_t count;
    GroupMessageEncryptedKey encryptedKey[0];
} GroupMessage;


@implementation CBPrivateKey (GroupEncryption)

- (NSData*) encryptGroupMessage: (NSData*)cleartext
                  forRecipients: (NSArray*)recipients
{
    NSMutableData* output = [NSMutableData dataWithCapacity: sizeof(GroupMessage)
                                            + recipients.count * sizeof(GroupMessageEncryptedKey)
                                            + cleartext.length + kCBEncryptedMessageOverhead];
    // Generate a random nonce and write it:
    CBNonce nonce = [CBPrivateKey randomNonce];
    [output appendBytes: &nonce length: sizeof(nonce)];

    // Generate a random session key-pair:
    CBPrivateKey* sessionKey = [CBPrivateKey generateKeyPair];
    NSData* sessionPrivateKeyData = sessionKey.keyData;

    // Write the recipient count, and the session's private key encrypted for each recipient:
    uint32_t bigCount = CFSwapInt32HostToBig((uint32_t)recipients.count);
    [output appendBytes: &bigCount length: sizeof(bigCount)];
    for (CBPublicKey* recipient in recipients) {
        // It's OK to reuse the same nonce, because each recipient public key is different
        [output appendData: [self encrypt: sessionPrivateKeyData
                                withNonce: nonce
                             forRecipient: recipient]];
    }
    // Finally append the ciphertext, encrypted with me as sender and session key as recipient:
    [output appendData: [self encrypt: cleartext
                            withNonce: nonce
                         forRecipient: sessionKey.publicKey]];
    return output;
}


- (NSData*) decryptGroupMessage: (NSData*)input
                     fromSender: (CBPublicKey*)sender
{
    // Read the header:
    size_t inputLen = input.length;
    if (inputLen < sizeof(GroupMessage))
        return nil;
    const GroupMessage* header = input.bytes;
    uint32_t count = CFSwapInt32BigToHost(header->count);
    if (inputLen < offsetof(GroupMessage, encryptedKey[count]))
        return nil;
    // Look at each recipient's encrypted data looking for one I can decrypt:
    NSData* sessionKeyData = nil;
    for (uint32_t i = 0; i < count; i++) {
        NSData* item = [NSData dataWithBytesNoCopy: (void*)&header->encryptedKey[i]
                                            length: sizeof(header->encryptedKey[i])
                                      freeWhenDone: NO];
        sessionKeyData = [self decrypt: item withNonce: header->nonce fromSender: sender];
        if (sessionKeyData)
            break;
    }
    if (!sessionKeyData)
        return nil; // Apparently it wasn't addressed to this key

    CBPrivateKey* sessionKey = [[CBPrivateKey alloc] initWithKeyData: sessionKeyData];
    if (!sessionKey)
        return nil;

    // Decrypt the ciphertext, which was encrypted with the session key as recipient:
    NSData* ciphertext = [NSData dataWithBytesNoCopy: (void*)&header->encryptedKey[count]
                                              length: input.length - offsetof(GroupMessage,
                                                                              encryptedKey[count])
                                        freeWhenDone: NO];
    return [sessionKey decrypt: ciphertext withNonce: header->nonce fromSender: sender];
}


@end