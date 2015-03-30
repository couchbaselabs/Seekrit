//
//  Mnemonicode_Test.m
//  Seekrit
//
//  Created by Jens Alfke on 3/28/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "NSData+Mnemonic.h"
#import "mnemonic.h"

@interface Mnemonicode_Test : XCTestCase

@end

@implementation Mnemonicode_Test
{
    NSData* randomData;
}

- (void) setUp {
    NSMutableData* d = [NSMutableData dataWithLength: 32];
    SecRandomCopyBytes(kSecRandomDefault, d.length, d.mutableBytes);
    randomData = d;
}

- (void) testRoundTrip {
    NSString* m = [randomData my_mnemonicWithFormat: @" x x x / x x x\n"];
    NSLog(@"mnemonic  = \n%@", m);
    NSError* error;
    NSData* decoded = [NSData my_dataFromMnemonic: m error: &error];
    XCTAssertEqualObjects(decoded, randomData);
}

- (void) testBadWord {
    NSError* error;
    NSData* decoded = [NSData my_dataFromMnemonic: @"virtual maser polka" error: &error];
    XCTAssertNil(decoded, @"Should have failed, got %@", decoded);
    XCTAssertEqualObjects(error.domain, @"mnemonicode");
    XCTAssertEqual(error.code, MN_EWORD);
    XCTAssertEqualObjects(error.userInfo[@"offset"], @8);
}

- (void) testBadNumberOfWords {
    NSError* error;
    NSData* decoded = [NSData my_dataFromMnemonic: @"virtual laser" error: &error];
    XCTAssertNil(decoded, @"Should have failed, got %@", decoded);
    XCTAssertEqualObjects(error.domain, @"mnemonicode");
    XCTAssertEqual(error.code, MN_EREM);
    XCTAssertEqualObjects(error.userInfo[@"offset"], @13);
}


@end
