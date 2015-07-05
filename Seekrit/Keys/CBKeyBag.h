//
//  CBKeyBag.h
//  Beanbag
//
//  Created by Jens Alfke on 3/3/14.
//  Copyright (c) 2014 The Mooseyard. All rights reserved.
//

#import "CBKey.h"
@class CBSymmetricKey;


/** Simple, lightweight (but secure) database of CBSymmetricKeys.
    The KeyBag is persisted to a single file that's encrypted using a master symmetric key
    stored in the Keychain. */
@interface CBKeyBag : NSObject

/** Opens or creates a KeyBag with an app-defined identifier.
    The file is stored in "~/Library/Application Support/$IDENTIFIER.keybag".
    The master key is stored in the Keychain under the given identifier. */
+ (instancetype) keyBagWithIdentifier: (NSString*)identifier
                                error: (NSError**)outError;

/** Opens or creates a KeyBag at the given path using the given master key. */
+ (instancetype) keyBagWithPath: (NSString*)path
                      masterKey: (CBSymmetricKey*)masterKey
                          error: (NSError**)outError;

/** Creates a new KeyBag that will be saved to the given path. */
- (instancetype) initNewWithPath: (NSString*)path
                       masterKey: (CBSymmetricKey*)masterKey;

/** The filesystem path to which the KeyBag is saved. */
@property (readonly) NSString* path;

/** Saves the KeyBag immediately. (The KeyBag will also auto-save changes.) */
- (BOOL) save: (NSError**)outError;

/** Adds a key. Returns YES if the key was new, NO if it already exists. */
- (BOOL) addKey: (CBSymmetricKey*)key;

/** Adds a key and associates it with the given identifier. */
- (void) addKey: (CBSymmetricKey*)key
     identifier: (NSString*)identifier;

/** Returns the key associated with the given identifier, or nil. */
- (CBSymmetricKey*) keyWithIdentifier: (NSString*)identifier;

/** Returns all identifiers that have keys associcated. */
@property (readonly) NSArray* allIdentifiers;

/** Decrypts a ciphertext, trying all appropriate keys.
    IMPORTANT: The ciphertext must contain a clue, i.e. must have been generated using
    -[CBSymmetricKey encryptWithClue:]. */
- (NSData*) decrypt: (NSData*)ciphertext;

/** Decrypts a ciphertext, trying all appropriate keys.
    Also returns the key that decripted it. */
- (NSData*) decrypt: (NSData*)encrypted
            usedKey: (CBSymmetricKey**)outKey;

@end
