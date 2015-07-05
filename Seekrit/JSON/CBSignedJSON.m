//
//  SignedJSON.m
//  People
//
//  Created by Jens Alfke on 8/16/11.
//  Copyright (c) 2011 Couchbase, Inc. All rights reserved.
//

#import "CBSignedJSON.h"
#import "CBCanonicalJSON.h"
#import "Logging.h"
#import <CommonCrypto/CommonDigest.h>


#define kExpiresUnit (60.0) // one minute

NSString* const kCBJSONSignatureProperty = @"(signed)";

NSString* const kCBSignedJSONErrorDomain = @"CBSignedJSON";



static NSData* CanonicalDigest(id jsonObject) {
    NSData* canonical = [CBCanonicalJSON canonicalData: jsonObject];
    struct {
        uint8_t bytes[20];
    } digest;
    CC_SHA1(canonical.bytes, (CC_LONG)canonical.length, digest.bytes);
    return [[NSData alloc] initWithBytes: &digest length: sizeof(digest)];
}

static NSString* CanonicalDigestString(id jsonObject) {
    return [CanonicalDigest(jsonObject) base64EncodedStringWithOptions: 0];
}

static NSData* DecodeBase64(id input) {
    if (![input isKindOfClass: [NSString class]])
        return nil;
    return [[NSData alloc] initWithBase64EncodedString: input
                                           options: NSDataBase64DecodingIgnoreUnknownCharacters];
}

static BOOL mkError(NSInteger code, NSError** outError) {
    if (outError)
        *outError = [NSError errorWithDomain: kCBSignedJSONErrorDomain code: code userInfo: nil];
    return NO;
}


static NSDateFormatter* getISO8601Formatter() {
    static NSDateFormatter* sFormatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Thanks to DenNukem's answer in http://stackoverflow.com/questions/399527/
        sFormatter = [[NSDateFormatter alloc] init];
        sFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssXXX";
        sFormatter.calendar = [[NSCalendar alloc] initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
        sFormatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US"];
        sFormatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    });
    return sFormatter;
}

static NSDate* parseDate(NSString* dateStr) {
    if (![dateStr isKindOfClass: [NSString class]])
        return nil;
    NSDateFormatter* fmt = getISO8601Formatter();
    @synchronized(fmt) {
        return [fmt dateFromString: dateStr];
    }
}

static NSString* formatDate(NSDate* date) {
    NSDateFormatter* fmt = getISO8601Formatter();
    @synchronized(fmt) {
        return [fmt stringFromDate: date];
    }
}




@implementation CBVerifyingPublicKey (JSON)

+ (NSDictionary*) signatureOfJSON: (id)jsonObject {
    if (![jsonObject isKindOfClass: [NSDictionary class]])
        return nil;
    id signature = jsonObject[kCBJSONSignatureProperty];
    if (![signature isKindOfClass: [NSDictionary class]])
        return nil;
    return signature;
}

+ (CBVerifyingPublicKey*) keyFromSignature:(NSDictionary*)signature {
    // Check whether this is actually signed JSON with a '(signed)' item in it:
    NSData* keyData = DecodeBase64(signature[@"key_25519"]);
    if (keyData)
        return [[CBVerifyingPublicKey alloc] initWithKeyData: keyData];
    return nil;
}

+ (NSDate*) dateOfSignature: (NSDictionary*)signature {
    return parseDate(signature[@"date"]);
}

+ (NSDate*) expirationDateOfSignature: (NSDictionary*)signature {
    id expiresObj = signature[@"expires"];
    if (!expiresObj)
        return [NSDate distantFuture];  // no expiration
    if (![expiresObj isKindOfClass: [NSNumber class]])
        return [NSDate distantPast];  // invalid expiration
    NSTimeInterval expires = [expiresObj doubleValue] * kExpiresUnit;
    return [[self dateOfSignature: signature] dateByAddingTimeInterval: expires];
}

+ (BOOL) isExpiredSignature: (NSDictionary*)signature {
    return [self expirationDateOfSignature: signature].timeIntervalSinceNow < 0;
}

/** Verifies a signature created by +signatureOfJSON. */
- (BOOL) verifySignature: (NSDictionary*)signature
                  ofJSON: (id)jsonObject
                   error: (NSError**)outError
{
    if ([[self class] isExpiredSignature: signature])
        return mkError(kCBSignedJSONErrorExpired, outError);
    NSData* digestData = DecodeBase64(signature[@"digest_SHA"]);
    if (!digestData) {
        return mkError(kCBSignedJSONErrorUnknownSignatureType, outError);
    } else if (![digestData isEqual: CanonicalDigest(jsonObject)]) {
        Warn(@"SignedJSON: Signature digest %@ doesn't match payload's %@; canonical JSON = %@",
             digestData, CanonicalDigest(jsonObject),
             [CBCanonicalJSON canonicalString: jsonObject]);
        return mkError(kCBSignedJSONErrorIncorrectDigest, outError);
    }
    NSData* sigData = [[NSData alloc] initWithBase64EncodedString: signature[@"sig"]
                                          options: NSDataBase64DecodingIgnoreUnknownCharacters];
    if (sigData.length != sizeof(CBSignature)) {
        return mkError(kCBSignedJSONErrorUnknownSignatureType, outError);
    }

    NSMutableDictionary* unsignedSignature = [signature mutableCopy];
    [unsignedSignature removeObjectForKey: @"sig"];
    if (![self verifySignature: *(const CBSignature*)sigData.bytes
                        ofData: [CBCanonicalJSON canonicalData: unsignedSignature]]) {
        return mkError(kCBSignedJSONErrorInvalidSignature, outError);
    }
    return YES;
}

/** Verifies a signed JSON object created by +addSignatureToJSON:. */
- (BOOL) verifySignedJSON: (NSDictionary*)jsonDict
                    error: (NSError**)outError
{
    NSDictionary *signature = [[self class] signatureOfJSON: jsonDict];
    if (!signature)
        return mkError(kCBSignedJSONErrorUnsigned, outError);
    NSMutableDictionary *unsignedDict = [jsonDict mutableCopy];
    [unsignedDict removeObjectForKey: kCBJSONSignatureProperty];
    return [self verifySignature: signature ofJSON: unsignedDict error: outError];
}


+ (CBVerifyingPublicKey*) signerOfJSON:(NSDictionary*)jsonDict
                        error: (NSError**)outError
{
    CBVerifyingPublicKey* key = [self keyFromSignature: [self signatureOfJSON: jsonDict]];
    if ([key verifySignedJSON: jsonDict error: outError])
        return key;
    return nil;
}

+ (CBVerifyingPublicKey*) signerOfSignature: (NSDictionary*)signature
                            ofJSON: (id)jsonObject
                             error: (NSError**)outError
{
    CBVerifyingPublicKey* key = [self keyFromSignature: signature];
    if ([key verifySignature: signature ofJSON: jsonObject error: outError])
        return key;
    return nil;
}


@end




@implementation CBSigningPrivateKey (JSON)

- (NSDictionary*) signatureOfJSON: (id)jsonObject
                     expiresAfter: (NSTimeInterval)expirationInterval
{
    NSString* keyStr = [self.publicKey.keyData base64EncodedStringWithOptions: 0];
    NSMutableDictionary* signature = [@{
        @"digest_SHA": CanonicalDigestString(jsonObject),
        @"key_25519": keyStr,
        @"date": formatDate([NSDate date])
    } mutableCopy];
    if (expirationInterval > 0.0)
        signature[@"expires"] = @(MAX(0, floor(expirationInterval / kExpiresUnit)));
    CBSignature sig = [self signData: [CBCanonicalJSON canonicalData: signature]];
    NSData* sigData = [NSData dataWithBytes: &sig length: sizeof(sig)];
    signature[@"sig"] = [sigData base64EncodedStringWithOptions: 0];
    return [signature copy];
}


- (NSDictionary*) addSignatureToJSON: (NSDictionary*)jsonDict
                        expiresAfter: (NSTimeInterval)expirationInterval
{
    NSMutableDictionary *signedDict = [jsonDict mutableCopy];
    [signedDict removeObjectForKey: kCBJSONSignatureProperty];
    NSDictionary *signature = [self signatureOfJSON: signedDict expiresAfter: expirationInterval];
    if (!signature)
        return nil;
    signedDict[kCBJSONSignatureProperty] = signature;
    return signedDict;
}

@end
