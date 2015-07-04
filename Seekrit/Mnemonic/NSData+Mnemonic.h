//
//  NSData+Mnemonic.h
//  MYUtilities
//
//  Created by Jens Alfke on 6/24/09.
//  Copyright 2009-2015 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSData (MYMnemonic)

/** Converts the data to a series of common English words that can be sent verbally to
    another person, for instance by reading them over the phone. Every four bytes of data
    produces three words. */
@property (readonly) NSString* my_mnemonic;

/** Same as .my_mnemonic but the format string allows control of the delimiters between words.
    Every alphabetic character in the format string will be replaced with a word, with the
    non-alphabetic characters echoed in between. The format string is repeated if necessary. */
- (NSString*) my_mnemonicWithFormat: (NSString*)format;

/** Converts a mnemonic string back to binary data. Capicalization and spacing/punctuation are
    ignored. If an error occurs, returns nil and sets `error` to an NSError with domain
    "mnemonicode", and a userInfo with a key "offset" whose value is the offset in the string
    at which the error occurred. */
+ (NSData*) my_dataFromMnemonic: (NSString*)mnemonic
                          error: (NSError**)error;

@end
