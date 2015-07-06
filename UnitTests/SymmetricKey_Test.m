//
//  SymmetricKey_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#import "CBKey+Private.h"
#import "CBSymmetricKey.h"
#import "CBKeyBag.h"


@interface CBKeyBag (Private)
+ (NSString*) pathForIdentifier: (NSString*)identifier;
@end


@interface SymmetricKey_Test : XCTestCase
@end

@implementation SymmetricKey_Test
{
    CBSymmetricKey* alice;
}

- (void)setUp {
    [super setUp];
    alice = [CBSymmetricKey generate];
    XCTAssert(alice != nil);
}

- (void)testEncrypt {
    NSLog(@"alice = %@ ", alice.keyData);
    XCTAssertEqual(alice.keyData.length, sizeof(CBRawKey));
    NSData* clear = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    NSLog(@"cleartext = %@", clear);
    NSData* cipher = [alice encrypt: clear];
    XCTAssert(cipher);
    NSLog(@"ciphertext= %@", cipher);

    CBSymmetricKey* alice2 = [[CBSymmetricKey alloc] initWithKeyData: alice.keyData];
    NSData* decrypted = [alice2 decrypt: cipher];
    NSLog(@"decrypted = %@", decrypted);
    XCTAssertEqualObjects(decrypted, clear);
}

- (void)testEncryptWithNonce {
    NSLog(@"alice = %@ ", alice.keyData);
    NSData* clear = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    NSLog(@"cleartext = %@", clear);
    CBNonce nonce = {{0x01, 0x02, 0x03}}; // rest all zeroes
    NSData* cipher = [alice encrypt: clear withNonce: nonce];
    XCTAssert(cipher);
    NSLog(@"ciphertext= %@", cipher);

    CBSymmetricKey* alice2 = [[CBSymmetricKey alloc] initWithKeyData: alice.keyData];
    NSData* decrypted = [alice2 decrypt: cipher withNonce: nonce];
    NSLog(@"decrypted = %@", decrypted);
    XCTAssertEqualObjects(decrypted, clear);
}



- (void) testKeyBag {
    [CBPrivateKey useTestKeychain];

    [[NSFileManager defaultManager] removeItemAtPath: [CBKeyBag pathForIdentifier: @"UnitTests"]
                                               error: nil];
    NSError* error;
    CBKeyBag* bag = [CBKeyBag keyBagWithIdentifier: @"UnitTests" error: &error];
    XCTAssertNotNil(bag, @"Couldn't create CBKeyBag: %@", error);
    NSLog(@"CBKeyBag created at %@", bag.path);

    CBSymmetricKey* key1 = [[CBSymmetricKey alloc] init];
    [bag addKey: key1 identifier: @"key1"];
    CBSymmetricKey* key2 = [[CBSymmetricKey alloc] init];
    [bag addKey: key2 identifier: @"key2"];

    XCTAssertEqual([bag keyWithIdentifier: @"key1"], key1);
    XCTAssertEqual([bag keyWithIdentifier: @"key2"], key2);

    NSData* cleartext = [@"ATTACK AT DAWN" dataUsingEncoding: NSUTF8StringEncoding];
    NSData* encrypted = [key1 encryptWithClue: cleartext];

    CBSymmetricKey* usedKey;
    NSData* decrypted = [bag decrypt: encrypted usedKey: &usedKey];
    XCTAssertEqualObjects(decrypted, cleartext);
    XCTAssertEqualObjects(usedKey, key1);

    XCTAssert([bag save: &error], @"Save failed: %@", error);

    bag = [CBKeyBag keyBagWithIdentifier: @"UnitTests" error: &error];
    XCTAssertNotNil(bag, @"Couldn't reopen CBKeyBag: %@", error);

    XCTAssertEqualObjects([bag keyWithIdentifier: @"key1"], key1);
    XCTAssertEqualObjects([bag keyWithIdentifier: @"key2"], key2);

    decrypted = [bag decrypt: encrypted usedKey: &usedKey];
    XCTAssertEqualObjects(decrypted, cleartext);
    XCTAssertEqualObjects(usedKey, key1);

    [[NSFileManager defaultManager] removeItemAtPath: bag.path error: NULL];
}


@end
