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
#import "CBEncryptingKey.h"
#import "CBEncryptingKey+Group.h"
#import "NSData+Mnemonic.h"


@interface Key_Test : XCTestCase
@end

@implementation Key_Test
{
    CBEncryptingKey* alice;
    CBEncryptingKey* bob;
}

- (void)setUp {
    [super setUp];
    alice = [CBEncryptingKey generate];
    bob = [CBEncryptingKey generate];
    XCTAssert(alice.publicKey != nil);
    XCTAssert(bob.publicKey != nil);
}

- (void)testBox {
    NSLog(@"alice = %@  /  %@", alice.keyData, alice.publicKey.keyData);
    NSLog(@"bob   = %@  /  %@", bob.keyData, bob.publicKey.keyData);
    NSData* clear = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    NSLog(@"cleartext = %@", clear);
    CBNonce nonce = {0x01, 0x02, 0x03}; // rest all zeroes
    NSData* cipher = [alice encrypt: clear withNonce: nonce forRecipient: bob.publicKey];
    XCTAssert(cipher);
    NSLog(@"ciphertext= %@", cipher);

    NSData* decrypted = [bob decrypt: cipher withNonce: nonce fromSender: alice.publicKey];
    NSLog(@"decrypted = %@", decrypted);
    XCTAssertEqualObjects(decrypted, clear);
}

- (void) testRecoverPublicKey {
    CBEncryptingKey* alice2 = [[CBEncryptingKey alloc] initWithKeyData: alice.keyData];
    XCTAssertEqualObjects(alice2.publicKey.keyData, alice.publicKey.keyData);
}

- (void) testNonces {
    CBNonce n = {0};
    n.bytes[23] = 200;
    [CBEncryptingKey incrementNonce: &n by: 1];
    XCTAssertEqual(n.bytes[23], 201);
    for (int i=0; i<23; i++)
        XCTAssertEqual(n.bytes[i], 0);

    [CBEncryptingKey incrementNonce: &n by: 100];
    XCTAssertEqual(n.bytes[23], 45);
    XCTAssertEqual(n.bytes[22], 1);
    for (int i=0; i<22; i++)
        XCTAssertEqual(n.bytes[i], 0);

    [CBEncryptingKey incrementNonce: &n by: -45];
    XCTAssertEqual(n.bytes[23], 0);
    XCTAssertEqual(n.bytes[22], 1);
    for (int i=0; i<22; i++)
        XCTAssertEqual(n.bytes[i], 0);

    memset(&n, 0, sizeof(n));
    [CBEncryptingKey incrementNonce: &n by: -1];
    for (int i=0; i<24; i++)
        XCTAssertEqual(n.bytes[i], 255);
}

- (void) testPasswords {
    NSData* salt = [@"SaltyMcNaCl" dataUsingEncoding: NSUTF8StringEncoding];
    uint32_t rounds = [CBEncryptingKey passphraseRoundsNeededForDelay: 0.5 withSalt: salt];
    NSLog(@"Rounds should be %d", rounds);
    XCTAssertGreaterThan(rounds, 100000);

    // Generate a key from a password:
    NSString* password = @"letmein123456";
    CBEncryptingKey* key = [CBEncryptingKey keyFromPassphrase: password
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
        CBEncryptingKey* priv = [CBEncryptingKey generate];
        [groupPrivate addObject: priv];
        [groupPublic addObject: priv.publicKey];
    }

    CBEncryptingKey* me = [CBEncryptingKey generate];

    NSData* clear = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    NSData* cipher = [me encryptGroupMessage: clear forRecipients: groupPublic];
    NSLog(@"Cipher = %@", cipher);

    for (CBEncryptingKey* member in groupPrivate) {
        NSData* decrypted = [member decryptGroupMessage: cipher fromSender: me.publicKey];
        XCTAssertEqualObjects(decrypted, clear);
    }

    CBEncryptingKey* stranger = [CBEncryptingKey generate];
    XCTAssertNil([stranger decryptGroupMessage: cipher fromSender: me.publicKey]);
}

#if !TARGET_OS_IPHONE
- (void) testKeychain {
    CBEncryptingKey* key = [CBEncryptingKey generate];
    XCTAssert([key addToKeychain: self.keychain
                      forService: @"unit-test"
                         account: @"testy-mc-tester"]);

    CBEncryptingKey* readKey = [CBEncryptingKey keyPairFromKeychain: self.keychain
                                                   forService: @"unit-test"
                                                      account: @"testy-mc-tester"];
    XCTAssertNotNil(readKey);
    XCTAssertEqualObjects(key.keyData, readKey.keyData);

    XCTAssertNil([CBEncryptingKey keyPairFromKeychain: self.keychain
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
