//
//  CBKeyBag.m
//  Beanbag
//
//  Created by Jens Alfke on 3/3/14.
//  Copyright (c) 2014 The Mooseyard. All rights reserved.
//

#import "CBKeyBag.h"
#import "CBKey+Private.h"
#import "CBSymmetricKey.h"
#import "MYBlockUtils.h"
#import "MYErrorUtils.h"
#import "Test.h"
#import <CommonCrypto/CommonCrypto.h>


@interface CBKeyBag  () <NSCoding>
@end


@implementation CBKeyBag
{
    NSString* _path;
    CBSymmetricKey* _masterKey;
    NSMutableDictionary* _store;        // maps clues to arrays of keys
    NSMutableDictionary* _byIdentifier;
    BOOL _dirty;
    BOOL _autosaving;
}

@synthesize path=_path;


+ (NSString*) pathForIdentifier: (NSString*)identifier {
    NSString* dir = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                        NSUserDomainMask, YES)[0];
    return [dir stringByAppendingPathComponent:
                      [identifier stringByAppendingPathExtension: @"keybag"]];
}


+ (instancetype) keyBagWithIdentifier: (NSString*)identifier
                                error: (NSError**)outError
{
    NSString* path = [self pathForIdentifier: identifier];

    NSString* appID = [[NSBundle mainBundle] bundleIdentifier];
    NSString* keyIdentifier = [NSString stringWithFormat: @"%@-KeyBag-%@", appID, identifier];
    CBSymmetricKey* masterKey = [CBSymmetricKey keyFromKeychainForService: @"KeyBag"
                                                                  account: keyIdentifier];
    if (!masterKey) {
        masterKey = [CBSymmetricKey generate];
        if (![masterKey addToKeychainForService: @"KeyBag" account: keyIdentifier error: outError])
            return nil;
    }
    return [self keyBagWithPath: path masterKey: masterKey error: outError];
}


+ (instancetype) keyBagWithPath: (NSString*)path
                      masterKey: (CBSymmetricKey*)masterKey
                          error: (NSError**)outError
{
    Assert(path);
    NSError* error;
    NSData* contents = [NSData dataWithContentsOfFile: path options: 0 error: &error];
    if (!contents) {
        if (!error.my_isFileNotFoundError) {
            if (outError)
                *outError = error;
            return nil;
        }
        // Create empty instance
        LogTo(KeyBag, @"Created at %@ with key %@", path, masterKey);
        return [[CBKeyBag alloc] initNewWithPath: path masterKey: masterKey];
    } else {
        if (masterKey) {
            contents = [masterKey decrypt: contents];
            if (!contents) {
                MYReturnError(outError, kCCDecodeError, NSOSStatusErrorDomain, @"Can't decrypt KeyBag");
                return nil;
            }
        }
        CBKeyBag* bag = [NSKeyedUnarchiver unarchiveObjectWithData: contents];
        if (!bag) {
            MYReturnError(outError, kCCDecodeError, NSOSStatusErrorDomain, @"Can't unarchive KeyBag");
            return nil;
        }
        bag->_path = path;
        bag->_masterKey = masterKey;
        LogTo(KeyBag, @"Loaded from %@ with key %@", path, masterKey);
        return bag;
    }
}


- (instancetype) initNewWithPath: (NSString*)path masterKey: (CBSymmetricKey*)masterKey {
    self = [super init];
    if (self) {
        _path = path.copy;
        _masterKey = masterKey;
        _store = [[NSMutableDictionary alloc] init];
        _byIdentifier = [[NSMutableDictionary alloc] init];
    }
    return self;
}

- (instancetype) initWithCoder: (NSCoder*)decoder {
    self = [super init];
    if (self) {
        _store = [decoder decodeObjectForKey: @"store"];
        _byIdentifier = [decoder decodeObjectForKey: @"byIdentifier"];
    }
    return self;
}

- (void) encodeWithCoder:(NSCoder *)encoder {
    [encoder encodeObject: _store forKey: @"store"];
    [encoder encodeObject: _byIdentifier forKey: @"byIdentifier"];
}


- (BOOL) save: (NSError**)outError {
    if (!_dirty)
        return YES;
    LogTo(KeyBag, @"Saving");
    Assert(_path);
    NSData* contents = [NSKeyedArchiver archivedDataWithRootObject: self];
    NSAssert(contents, @"archiving failed");
    if (_masterKey)
        contents = [_masterKey encrypt: contents];
    if (![contents writeToFile: _path options: NSDataWritingAtomic error: outError])
        return NO;
    _dirty = NO;
    return YES;
}

- (void) autosave {
    if (_dirty && !_autosaving) {
        _autosaving = YES;
        MYAfterDelay(0.5, ^{
            self->_autosaving = NO;
            NSError* error;
            if (![self save: &error])
                Warn(@"Failed to save %@: %@", self, error);
        });
    }
}

- (void) setNeedsSave {
    _dirty = YES;
    [self autosave];
}


- (NSArray*) getKeysForClue: (CBKeyClue)clue {
    return _store[@(clue)];
}


- (BOOL) addKey: (CBSymmetricKey*)key {
    Assert(key);
    id clue = @(key.clue);
    NSMutableArray* keys = _store[clue];
    if (!keys) {
        _store[clue] = [[NSMutableArray alloc] initWithObjects: key, nil];
        [self setNeedsSave];
        LogTo(KeyBag, @"Added %@", key);
        return YES;
    } else if (![keys containsObject: key]) {
        [keys insertObject: key atIndex: 0]; // newest keys go first
        [self setNeedsSave];
        LogTo(KeyBag, @"Added %@", key);
        return YES;
    }
    return NO;
}


- (void) addKey: (CBSymmetricKey*)key identifier: (NSString*)identifier {
    [self addKey: key];
    if (![key isEqual: _byIdentifier[identifier]]) {
        _byIdentifier[identifier] = key;
        [self setNeedsSave];
        LogTo(KeyBag, @"'%@' --> %@", identifier, key);
    }
}

- (CBSymmetricKey*) keyWithIdentifier:(NSString *)identifier {
    return _byIdentifier[identifier];
}

- (NSArray*) allIdentifiers {
    return _byIdentifier.allKeys;
}


- (NSData*) decrypt: (NSData*)encrypted
            usedKey: (CBSymmetricKey**)outUsedKey
{
    CBKeyClue clue = [CBSymmetricKey clueForEncryptedData: encrypted];
    for (CBSymmetricKey* key in _store[@(clue)]) {
        NSData* decrypted = [key decryptWithClue: encrypted];
        if (decrypted) {
            LogTo(KeyBag, @"Decrypted message using %@", key);
            if (outUsedKey)
                *outUsedKey = key;
            return decrypted;
        }
    }
    LogTo(KeyBag, @"Failed to decrypt message (clue=%04x)", clue);
    return nil;
}

- (NSData*) decrypt: (NSData*)encrypted {
    return [self decrypt: encrypted usedKey: NULL];
}

+ (NSString*) keyType {
    return @"KeyBag";
}

- (NSString*) keyType {
    return @"KeyBag";
}


@end
