//
//  SymmetricKey_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#import "CBSymmetricKey.h"


@interface CBPrivateKey ()
@property (readonly) NSData* keyData;
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
    CBNonce nonce = {0x01, 0x02, 0x03}; // rest all zeroes
    NSData* cipher = [alice encrypt: clear withNonce: nonce];
    XCTAssert(cipher);
    NSLog(@"ciphertext= %@", cipher);

    CBSymmetricKey* alice2 = [[CBSymmetricKey alloc] initWithKeyData: alice.keyData];
    NSData* decrypted = [alice2 decrypt: cipher withNonce: nonce];
    NSLog(@"decrypted = %@", decrypted);
    XCTAssertEqualObjects(decrypted, clear);
}


@end
