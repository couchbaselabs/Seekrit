//
//  SignedJSON_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 8/27/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <XCTest/XCTest.h>
#import "CBKey.h"
#import "SignedJSON.h"
#import "CanonicalJSON.h"


@interface SignedJSON_Test : XCTestCase
@end

@implementation SignedJSON_Test
{
    CBPrivateKey* key;
}

- (void)setUp {
    [super setUp];
    key = [CBPrivateKey generateKeyPair];
}

- (void)testSignedJSON {
    NSDictionary* json = @{@"foo": @1234, @"bar": @[@"hi", @"there"]};
    NSDate* exp = [NSDate dateWithTimeIntervalSinceNow: 60*60];
    NSDictionary* signature = [key signatureOfJSON: json expiresAt: exp];
    XCTAssert(signature);
    NSLog(@"Signature = %@", [CanonicalJSON canonicalString: signature]);

    NSDate* date = [CBPublicKey dateOfSignature: signature];
    XCTAssert(date);
    XCTAssert(fabs(date.timeIntervalSinceNow) < 2.0);
    XCTAssert(![CBPublicKey isExpiredSignature: signature]);
    XCTAssert([key.publicKey verifySignature: signature ofJSON: json]);
}

@end
