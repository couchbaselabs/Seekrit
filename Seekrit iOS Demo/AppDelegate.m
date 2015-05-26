//
//  AppDelegate.m
//  Seekrit iOS Demo
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "AppDelegate.h"
#import "CBKey.h"


@interface AppDelegate ()
@end


@implementation AppDelegate

@synthesize privateKey=_privateKey;


- (BOOL)application:(UIApplication *)application
        didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    _privateKey = [CBPrivateKey keyFromKeychainForService: @"Seekrit" account: @"me"];
    if (!_privateKey) {
        _privateKey = [CBPrivateKey generateKeyPair];
        [_privateKey addToKeychainForService: @"Seekrit" account: @"me"];
        NSLog(@"Generated key pair");
    }
    NSLog(@"Public key = %@", _privateKey.publicKey.keyData);
    return YES;
}

@end
