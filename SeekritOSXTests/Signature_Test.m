//
//  Signature_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 5/25/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#import "CBSigningKey.h"
#import "NSData+Mnemonic.h"


@interface CBPrivateKey ()
@property (readonly) NSData* keyData;
@end


@interface Signature_Test : XCTestCase
@end

@implementation Signature_Test
{
    CBSigningKey* alice;
    CBSigningKey* bob;
}

- (void)setUp {
    [super setUp];
    alice = [CBSigningKey generate];
    bob = [CBSigningKey generate];
    XCTAssert(alice.publicKey != nil);
    XCTAssert(bob.publicKey != nil);
}

- (void) testRecoverPublicKey {
    CBSigningKey* alice2 = [[CBSigningKey alloc] initWithKeyData: alice.keyData];
    XCTAssertEqualObjects(alice2.publicKey.keyData, alice.publicKey.keyData);
}

- (void) testSignatures {
    NSLog(@"alice = %@  /  %@", alice.keyData, alice.publicKey.keyData);
    NSData* message = [@"this is the cleartext message right here!" dataUsingEncoding: NSUTF8StringEncoding];
    CBSignature signature = [alice signData: message];
    NSLog(@"Signature = %@", [NSData dataWithBytes: &signature length: sizeof(signature)]);

    XCTAssert([alice.publicKey verifySignature: signature ofData: message]);

    NSData* pubKeyData = alice.publicKey.keyData;
    CBSigningPublicKey* pubKey = [[CBSigningPublicKey alloc] initWithKeyData: pubKeyData];
    XCTAssert([pubKey verifySignature: signature ofData: message]);
}

@end
