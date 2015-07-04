//
//  NSData+Mnemonic.m
//  MYUtilities
//
//  Created by Jens Alfke on 6/24/09.
//  Copyright 2009-2015 Jens Alfke. All rights reserved.
//

#import "NSData+Mnemonic.h"
#import "mnemonic.h"


@implementation NSData (Mnemonic)

- (NSString*) my_mnemonic {
    return [self my_mnemonicWithFormat: nil];
}

- (NSString*) my_mnemonicWithFormat: (NSString*)format {
    NSMutableData *chars = [NSMutableData dataWithLength: 10*mn_words_required((int)self.length)];
    if (!chars)
        return nil;
    int result = mn_encode((void*)self.bytes, (int)self.length,
                           chars.mutableBytes, (int)chars.length,
                           format ? (char*)format.UTF8String : MN_FDEFAULT);
    if (result != 0) {
        NSLog(@"Warning: Mnemonic encoder failed: err=%i",result);
        return nil;
    }
    return [[NSString alloc] initWithUTF8String: chars.mutableBytes];
}

// variant of mn_decode (in mnemonic.c) that returns the error position.
static int mn_decode2 (const char *src, void *dest, int destsize, const char **errorPos) {
    mn_index index;
    int offset = 0;

    while ((index = mn_next_word_index ((char**)&src)) != 0) {
        (void) mn_decode_word_index (index, dest, destsize, &offset);
    }
    if (errorPos != NULL)
        *errorPos = src;
    if (index == 0 && *src != 0)
        return MN_EWORD;
    int status = mn_decode_word_index (MN_EOF, dest, destsize, &offset);
    if (status < 0)
        return status;
    return offset;
}


+ (NSData*) my_dataFromMnemonic: (NSString*)mnemonic error: (NSError**)outError {
    const char* src = mnemonic.UTF8String;
    uint8_t dst[256];
    const char* errorPos;
    int result = mn_decode2(src, dst, sizeof(dst), &errorPos);
    if (result >= 0)
        return [[NSData alloc] initWithBytes: dst length: result];
    // Error:
    if (outError) {
        *outError = [NSError errorWithDomain: @"mnemonicode" code: result
                                    userInfo: @{@"offset": @(errorPos-src)}];
    }
    return nil;
}

@end
