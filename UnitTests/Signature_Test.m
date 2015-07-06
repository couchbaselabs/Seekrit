//
//  Signature_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#import "CBSigningPrivateKey.h"
#import "CBEncryptingPrivateKey.h"


@interface CBPrivateKey ()
@property (readonly) NSData* keyData;
@end


@interface Signature_Test : XCTestCase
@end

@implementation Signature_Test
{
    CBSigningPrivateKey* alice;
    CBSigningPrivateKey* bob;
}

- (void)setUp {
    [super setUp];
    alice = [CBSigningPrivateKey generate];
    bob = [CBSigningPrivateKey generate];
    XCTAssert(alice.publicKey != nil);
    XCTAssert(bob.publicKey != nil);
}

- (void) testRecoverPublicKey {
    CBSigningPrivateKey* alice2 = [[CBSigningPrivateKey alloc] initWithKeyData: alice.keyData];
    XCTAssertEqualObjects(alice2.publicKey.keyData, alice.publicKey.keyData);
}

- (void) testSignatures {
    NSLog(@"alice = %@  /  %@", alice.keyData, alice.publicKey.keyData);
    NSData* message = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    CBSignature signature = [alice signData: message];
    NSLog(@"Signature = %@", [NSData dataWithBytes: &signature length: sizeof(signature)]);

    XCTAssert([alice.publicKey verifySignature: signature ofData: message]);

    NSData* pubKeyData = alice.publicKey.keyData;
    CBVerifyingPublicKey* pubKey = [[CBVerifyingPublicKey alloc] initWithKeyData: pubKeyData];
    XCTAssert([pubKey verifySignature: signature ofData: message]);
}

- (void) testEncryptingConversion {
    CBEncryptingPrivateKey* aliceEncrypt = alice.asEncryptingKey;
    CBEncryptingPublicKey* alicePublicEncrypt = alice.publicKey.asEncryptingPublicKey;
    XCTAssertEqualObjects(alicePublicEncrypt, aliceEncrypt.publicKey);

    CBEncryptingPrivateKey* bobEncrypt = bob.asEncryptingKey;
    CBEncryptingPublicKey* bobPublicEncrypt = bob.publicKey.asEncryptingPublicKey;

    NSData* clear = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    NSLog(@"cleartext = %@", clear);
    CBNonce nonce = {{0x01, 0x02, 0x03}}; // rest all zeroes
    NSData* cipher = [aliceEncrypt encrypt: clear withNonce: nonce forRecipient: bobPublicEncrypt];
    XCTAssert(cipher);
    NSLog(@"ciphertext= %@", cipher);

    NSData* decrypted = [bobEncrypt decrypt: cipher withNonce: nonce fromSender: alicePublicEncrypt];
    NSLog(@"decrypted = %@", decrypted);
    XCTAssertEqualObjects(decrypted, clear);
}

@end
