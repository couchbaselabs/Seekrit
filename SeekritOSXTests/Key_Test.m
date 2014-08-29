//
//  Key_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 8/25/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <XCTest/XCTest.h>
#import "CBKey.h"
#import "CBKey+Group.h"
#import "curve_sigs.h"


@interface Key_Test : XCTestCase
@end

@implementation Key_Test
{
    CBPrivateKey* alice;
    CBPrivateKey* bob;
}

- (void)setUp {
    [super setUp];
    alice = [CBPrivateKey generateKeyPair];
    bob = [CBPrivateKey generateKeyPair];
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
    CBPrivateKey* alice2 = [[CBPrivateKey alloc] initWithKeyData: alice.keyData];
    XCTAssertEqualObjects(alice2.publicKey.keyData, alice.publicKey.keyData);
}

- (void) testRawSignatures {
    CBRawKey pubkey, privkey;
    SecRandomCopyBytes(kSecRandomDefault, 32, privkey.bytes);
    privkey.bytes[0] &= 248;
    privkey.bytes[31] &= 63;
    privkey.bytes[31] |= 64;
    curve25519_keygen(pubkey.bytes, privkey.bytes);

    // Verify that Key classes derive the same public key from the same private:
    CBPrivateKey* privObj = [[CBPrivateKey alloc] initWithRawKey: privkey];
    CBPublicKey* pubObj = [[CBPublicKey alloc] initWithRawKey: pubkey];
    XCTAssertEqualObjects(privObj.publicKey.keyData, pubObj.keyData);

    uint8_t signature[64], random[64];
    SecRandomCopyBytes(kSecRandomDefault, 64, random);
    char msg[] = "this is the cleartext message right here!";
    XCTAssertEqual(curve25519_sign(signature, privkey.bytes, (void*)msg, strlen(msg), random), 0);

    XCTAssertEqual(curve25519_verify(signature, pubkey.bytes, (void*)msg, strlen(msg)), 0);

    // Test PublicKey verifying signature generated by C API:
    CBSignature sigObj = [privObj signDigest: msg length: strlen(msg)];
    XCTAssert([pubObj verifySignature: sigObj ofDigest: msg length: strlen(msg)]);
    XCTAssert([privObj.publicKey verifySignature: sigObj ofDigest: msg length: strlen(msg)]);
}

- (void) testSignatures {
    NSLog(@"alice = %@  /  %@", alice.keyData, alice.publicKey.keyData);
    NSData* message = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    CBSignature signature = [alice sign: message];
    NSLog(@"Signature = %@", [NSData dataWithBytes: &signature length: sizeof(signature)]);

    XCTAssert([alice.publicKey verifySignature: signature ofData: message]);
}

- (void) testNonces {
    CBNonce n = {0};
    n.bytes[23] = 200;
    [CBPrivateKey incrementNonce: &n by: 1];
    XCTAssertEqual(n.bytes[23], 201);
    for (int i=0; i<23; i++)
        XCTAssertEqual(n.bytes[i], 0);

    [CBPrivateKey incrementNonce: &n by: 100];
    XCTAssertEqual(n.bytes[23], 45);
    XCTAssertEqual(n.bytes[22], 1);
    for (int i=0; i<22; i++)
        XCTAssertEqual(n.bytes[i], 0);

    [CBPrivateKey incrementNonce: &n by: -45];
    XCTAssertEqual(n.bytes[23], 0);
    XCTAssertEqual(n.bytes[22], 1);
    for (int i=0; i<22; i++)
        XCTAssertEqual(n.bytes[i], 0);

    memset(&n, 0, sizeof(n));
    [CBPrivateKey incrementNonce: &n by: -1];
    for (int i=0; i<24; i++)
        XCTAssertEqual(n.bytes[i], 255);
}

- (void) testPasswords {
    NSData* salt = [@"SaltyMcNaCl" dataUsingEncoding: NSUTF8StringEncoding];
    uint32_t rounds = [CBPrivateKey passphraseRoundsNeededForDelay: 0.5 withSalt: salt];
    NSLog(@"Rounds should be %d", rounds);
    XCTAssertGreaterThan(rounds, 100000);

    // Generate a key from a password:
    NSString* password = @"letmein123456";
    CBPrivateKey* key = [CBPrivateKey keyPairFromPassphrase: password
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
        CBPrivateKey* priv = [CBPrivateKey generateKeyPair];
        [groupPrivate addObject: priv];
        [groupPublic addObject: priv.publicKey];
    }

    CBPrivateKey* me = [CBPrivateKey generateKeyPair];

    NSData* clear = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    NSData* cipher = [me encryptGroupMessage: clear forRecipients: groupPublic];
    NSLog(@"Cipher = %@", cipher);

    for (CBPrivateKey* member in groupPrivate) {
        NSData* decrypted = [member decryptGroupMessage: cipher fromSender: me.publicKey];
        XCTAssertEqualObjects(decrypted, clear);
    }

    CBPrivateKey* stranger = [CBPrivateKey generateKeyPair];
    XCTAssertNil([stranger decryptGroupMessage: cipher fromSender: me.publicKey]);
}

- (void) testKeychain {
    CBPrivateKey* key = [CBPrivateKey generateKeyPair];
    XCTAssert([key addToKeychain: self.keychain
                     withService: @"unit-test"
                         account: @"testy-mc-tester"]);

    CBPrivateKey* readKey = [CBPrivateKey keyPairFromKeychain: self.keychain
                                                  withService: @"unit-test"
                                                      account: @"testy-mc-tester"];
    XCTAssertNotNil(readKey);
    XCTAssertEqualObjects(key.keyData, readKey.keyData);

    XCTAssertNil([CBPrivateKey keyPairFromKeychain: self.keychain
                                       withService: @"unit-test"
                                           account: @"frobozz"]);
}


- (CBKeychainRef) keychain {
    static CBKeychainRef sTestKeychain;
#if !TARGET_OS_IPHONE
    if (!sTestKeychain) {
        NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent: @"beanbag_test.keychain"];
        NSLog(@"Creating keychain at %@", path);
        [[NSFileManager defaultManager] removeItemAtPath: path error: NULL];
        XCTAssertEqual(SecKeychainCreate(path.fileSystemRepresentation, 6, "foobar", NO, NULL, &sTestKeychain), noErr);
    }
#endif
    return sTestKeychain;
}


@end
