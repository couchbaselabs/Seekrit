//
//  CBKeyBag.h
//  Beanbag
//
//  Created by Jens Alfke on 3/3/14.
//  Copyright (c) 2014 The Mooseyard. All rights reserved.
//

#import "CBKey.h"
@class CBSymmetricKey;


/** Simple, lightweight database of symmetric keys.
    The KeyBag is persisted to a single file that's encrypted using a master symmetric key
    stored in the Keychain. */
@interface CBKeyBag : NSObject

+ (instancetype) keyBagWithIdentifier: (NSString*)identifier
                                error: (NSError**)outError;

+ (instancetype) keyBagWithPath: (NSString*)path
                      masterKey: (CBSymmetricKey*)masterKey
                          error: (NSError**)outError;

- (instancetype) initNewWithPath: (NSString*)path
                       masterKey: (CBSymmetricKey*)masterKey;

@property (readonly) NSString* path;

- (BOOL) save: (NSError**)outError;

- (BOOL) addKey: (CBSymmetricKey*)key;

- (void) addKey: (CBSymmetricKey*)key
     identifier: (NSString*)identifier;

@property (readonly) NSArray* allIdentifiers;

- (CBSymmetricKey*) keyWithIdentifier: (NSString*)identifier;

- (NSData*) decrypt: (NSData*)ciphertext;

- (NSData*) decrypt: (NSData*)encrypted
            usedKey: (CBSymmetricKey**)outKey;

@end
