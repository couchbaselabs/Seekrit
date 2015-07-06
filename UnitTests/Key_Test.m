//
//  Key_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#import "CBKey+Private.h"
#import "CBEncryptingPrivateKey.h"
#import "CBEncryptingPrivateKey+Group.h"


@interface Key_Test : XCTestCase
@end

@implementation Key_Test
{
    CBEncryptingPrivateKey* alice;
    CBEncryptingPrivateKey* bob;
}

- (void)setUp {
    [super setUp];
    alice = [CBEncryptingPrivateKey generate];
    bob = [CBEncryptingPrivateKey generate];
    XCTAssert(alice.publicKey != nil);
    XCTAssert(bob.publicKey != nil);
}

- (void)testBox {
    NSLog(@"alice = %@  /  %@", alice.keyData, alice.publicKey.keyData);
    NSLog(@"bob   = %@  /  %@", bob.keyData, bob.publicKey.keyData);
    NSData* clear = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    NSLog(@"cleartext = %@", clear);
    CBNonce nonce = {{0x01, 0x02, 0x03}}; // rest all zeroes
    NSData* cipher = [alice encrypt: clear withNonce: nonce forRecipient: bob.publicKey];
    XCTAssert(cipher);
    NSLog(@"ciphertext= %@", cipher);

    NSData* decrypted = [bob decrypt: cipher withNonce: nonce fromSender: alice.publicKey];
    NSLog(@"decrypted = %@", decrypted);
    XCTAssertEqualObjects(decrypted, clear);
}

- (void) testRecoverPublicKey {
    CBEncryptingPrivateKey* alice2 = [[CBEncryptingPrivateKey alloc] initWithKeyData: alice.keyData];
    XCTAssertEqualObjects(alice2.publicKey.keyData, alice.publicKey.keyData);
}

- (void) testNonces {
    CBNonce n = {{0}};
    n.bytes[23] = 200;
    [CBEncryptingPrivateKey incrementNonce: &n by: 1];
    XCTAssertEqual(n.bytes[23], 201);
    for (int i=0; i<23; i++)
        XCTAssertEqual(n.bytes[i], 0);

    [CBEncryptingPrivateKey incrementNonce: &n by: 100];
    XCTAssertEqual(n.bytes[23], 45);
    XCTAssertEqual(n.bytes[22], 1);
    for (int i=0; i<22; i++)
        XCTAssertEqual(n.bytes[i], 0);

    [CBEncryptingPrivateKey incrementNonce: &n by: -45];
    XCTAssertEqual(n.bytes[23], 0);
    XCTAssertEqual(n.bytes[22], 1);
    for (int i=0; i<22; i++)
        XCTAssertEqual(n.bytes[i], 0);

    memset(&n, 0, sizeof(n));
    [CBEncryptingPrivateKey incrementNonce: &n by: -1];
    for (int i=0; i<24; i++)
        XCTAssertEqual(n.bytes[i], 255);
}

- (void) testPasswords {
    NSData* salt = [@"SaltyMcNaCl" dataUsingEncoding: NSUTF8StringEncoding];
    uint32_t rounds = [CBEncryptingPrivateKey passphraseRoundsNeededForDelay: 0.5 withSalt: salt];
    NSLog(@"Rounds should be %d", rounds);
    XCTAssertGreaterThan(rounds, 100000);

    // Generate a key from a password:
    NSString* password = @"letmein123456";
    CBEncryptingPrivateKey* key = [CBEncryptingPrivateKey keyFromPassphrase: password
                                        withSalt: salt
                                          rounds: rounds];
    NSLog(@"Derived key = %@", key.keyData);
    XCTAssertNotNil(key);
}

- (void) testGroupEncryption {
    // Create a bunch of recipients:
    const size_t n = 10;
    NSMutableArray* groupPrivate = [NSMutableArray array];
    NSMutableArray* groupPublic = [NSMutableArray array];
    for (size_t i=0; i<n; ++i) {
        CBEncryptingPrivateKey* priv = [CBEncryptingPrivateKey generate];
        [groupPrivate addObject: priv];
        [groupPublic addObject: priv.publicKey];
    }

    CBEncryptingPrivateKey* me = [CBEncryptingPrivateKey generate];

    NSData* clear = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    NSData* cipher = [me encryptGroupMessage: clear forRecipients: groupPublic];
    NSLog(@"Cipher = %@", cipher);

    for (CBEncryptingPrivateKey* member in groupPrivate) {
        NSData* decrypted = [member decryptGroupMessage: cipher fromSender: me.publicKey];
        XCTAssertEqualObjects(decrypted, clear);
    }

    CBEncryptingPrivateKey* stranger = [CBEncryptingPrivateKey generate];
    XCTAssertNil([stranger decryptGroupMessage: cipher fromSender: me.publicKey]);
}

#if !TARGET_OS_IPHONE
- (void) testKeychain {
    CBEncryptingPrivateKey* key = [CBEncryptingPrivateKey generate];
    XCTAssert([key addToKeychain: self.keychain
                      forService: @"unit-test"
                         account: @"testy-mc-tester"
                           error: nil]);

    CBEncryptingPrivateKey* readKey = [CBEncryptingPrivateKey keyPairFromKeychain: self.keychain
                                                   forService: @"unit-test"
                                                      account: @"testy-mc-tester"];
    XCTAssertNotNil(readKey);
    XCTAssertEqualObjects(key.keyData, readKey.keyData);

    XCTAssertNil([CBEncryptingPrivateKey keyPairFromKeychain: self.keychain
                                        forService: @"unit-test"
                                           account: @"frobozz"]);
}
#endif


#if !TARGET_OS_IPHONE
- (SecKeychainRef) keychain {
    static SecKeychainRef sTestKeychain;
    if (!sTestKeychain) {
        NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent: @"beanbag_test.keychain"];
        NSLog(@"Creating keychain at %@", path);
        [[NSFileManager defaultManager] removeItemAtPath: path error: NULL];
        XCTAssertEqual(SecKeychainCreate(path.fileSystemRepresentation, 6, "foobar", NO, NULL, &sTestKeychain), noErr);
    }
    return sTestKeychain;
}
#endif


@end
