//
//  CBKey+Private.h
//  Seekrit
//
//  Created by Jens Alfke on 5/26/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBKey.h"


/** Seed data to create a key-pair. (256 bits, 32 bytes) */
typedef struct {
    uint8_t bytes[32];
} CBKeySeed;


@interface CBKey ()
@property (readonly) NSData* keyData;
@property (readonly) CBRawKey rawKey;
@end


@interface CBPrivateKey ()
- (instancetype)initWithSeed: (CBKeySeed)seed; // called by +keyFromPassphrase:
#if DEBUG
+ (void) useTestKeychain; // Unit tests should use this
#endif
@end
