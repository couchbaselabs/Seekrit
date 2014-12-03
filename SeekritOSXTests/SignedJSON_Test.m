//
//  SignedJSON_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 8/27/14.
//  Copyright (c) 2014 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#import "CBKey.h"
#import "SignedJSON.h"
#import "CanonicalJSON.h"


static NSString* jsonString(id obj) {
    NSData* data = [NSJSONSerialization dataWithJSONObject: obj
                                                   options: NSJSONWritingPrettyPrinted
                                                     error: NULL];
    return [[NSString alloc] initWithData: data encoding: NSUTF8StringEncoding];
}


@interface SignedJSON_Test : XCTestCase
@end

@implementation SignedJSON_Test
{
    CBPrivateKey* privateKey;
}

- (void)setUp {
    [super setUp];
    privateKey = [CBPrivateKey generateKeyPair];
}

- (void)testSignedJSON {
    NSDictionary* json = @{@"foo": @1234, @"bar": @[@"hi", @"there"]};
    NSDictionary* signature = [privateKey signatureOfJSON: json expiresAfter: 60*60];
    XCTAssert(signature);
    NSLog(@"Signature = %@", jsonString(signature));

    XCTAssert([privateKey.publicKey verifySignature: signature ofJSON: json]);
    XCTAssertEqualObjects([CBPublicKey signerOfSignature: signature ofJSON: json],
                          privateKey.publicKey);

    NSDate* date = [CBPublicKey dateOfSignature: signature];
    XCTAssert(date);
    XCTAssert(fabs(date.timeIntervalSinceNow) < 2.0);

    XCTAssert(![CBPublicKey isExpiredSignature: signature]);
    NSDate* exp = [CBPublicKey expirationDateOfSignature: signature];
    XCTAssertNotNil(exp);
    NSTimeInterval remaining = exp.timeIntervalSinceNow;
    XCTAssertGreaterThan(remaining, 59*60);
    XCTAssertLessThan(remaining, 60*60);


    NSDictionary* signedJSON = [privateKey addSignatureToJSON: json expiresAfter: 60*60];
    ;
    NSLog(@"Signed JSON = %@", jsonString(signedJSON));
    XCTAssert(signedJSON);
    for (NSString* key in json)
        XCTAssertEqualObjects(signedJSON[key], json[key]);
    XCTAssertNotNil([CBPublicKey signatureOfJSON: signedJSON]);
}

@end
