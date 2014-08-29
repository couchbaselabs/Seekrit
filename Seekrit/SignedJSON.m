//
//  SignedJSON.m
//  People
//
//  Created by Jens Alfke on 8/16/11.
//  Copyright (c) 2011 Couchbase, Inc. All rights reserved.
//

#import "SignedJSON.h"
#import "CanonicalJSON.h"
#import <CommonCrypto/CommonDigest.h>


#define kExpiresUnit (60.0) // one minute


NSString* const kJSONSignatureProperty = @"(signed)";

#define kKeyType @"25519"


static NSData* CanonicalDigest(id jsonObject) {
    NSData* canonical = [CanonicalJSON canonicalData: jsonObject];
    struct {
        uint8_t bytes[20];
    } digest;
    CC_SHA1(canonical.bytes, (CC_LONG)canonical.length, digest.bytes);
    return [[NSData alloc] initWithBytes: &digest length: sizeof(digest)];
}

static NSString* CanonicalDigestString(id jsonObject) {
    return [CanonicalDigest(jsonObject) base64EncodedStringWithOptions: 0];
}

static NSData* ParseTypedData(NSString* expectedType, id input) {
    if (![input isKindOfClass: [NSArray class]])
        return nil;
    if ([input count] != 2 || ![input[0] isEqual: expectedType])
        return nil;
    return [[NSData alloc] initWithBase64EncodedString: input[1]
                                           options: NSDataBase64DecodingIgnoreUnknownCharacters];
}


static NSDateFormatter* getISO8601Formatter() {
    static NSDateFormatter* sFormatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Thanks to DenNukem's answer in http://stackoverflow.com/questions/399527/
        sFormatter = [[NSDateFormatter alloc] init];
        sFormatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssXXX";
        sFormatter.calendar = [[NSCalendar alloc] initWithCalendarIdentifier:NSGregorianCalendar];
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




@implementation CBPublicKey (JSON)

+ (NSDictionary*) signatureFromJSON: (id)jsonObject {
    if (![jsonObject isKindOfClass: [NSDictionary class]])
        return nil;
    id signature = jsonObject[kJSONSignatureProperty];
    if (![signature isKindOfClass: [NSDictionary class]])
        return nil;
    return signature;
}

+ (CBPublicKey*) keyFromSignature:(NSDictionary*)signature {
    // Check whether this is actually signed JSON with a '(signed)' item in it:
    NSData* keyData = ParseTypedData(kKeyType, signature[@"key"]);
    if (keyData)
        return [[CBPublicKey alloc] initWithKeyData: keyData];
    return nil;
}

+ (NSDate*) dateOfSignature: (NSDictionary*)signature {
    return parseDate(signature[@"date"]);
}

+ (BOOL) isExpiredSignature: (NSDictionary*)signature {
    id expiresObj = signature[@"expires"];
    if (![expiresObj isKindOfClass: [NSNumber class]])
          return NO;
    double expires = [expiresObj doubleValue];
    if (expires <= 0.0)
        return NO;
    NSDate* date = [self dateOfSignature: signature];
    if (!date)
        return NO;
    return -[date timeIntervalSinceNow] > (expires * kExpiresUnit);
}

/** Verifies a signature created by +signatureOfJSON. */
- (BOOL) verifySignature: (NSDictionary*)signature ofJSON: (id)jsonObject {
    if ([[self class] isExpiredSignature: signature])
        return NO;
    NSData* digestData = ParseTypedData(@"SHA1", signature[@"digest"]);
    if (!digestData || ![digestData isEqual: CanonicalDigest(jsonObject)]) {
        NSLog(@"Warning: SignedJSON: Signature digest %@ doesn't match payload's %@; canonical JSON = %@",
             digestData, CanonicalDigest(jsonObject),
             [CanonicalJSON canonicalString: jsonObject]);
        return NO;
    }
    NSData* sigData = [[NSData alloc] initWithBase64EncodedString: signature[@"sig"]
                                          options: NSDataBase64DecodingIgnoreUnknownCharacters];
    if (sigData.length != sizeof(CBSignature))
        return NO;

    NSMutableDictionary* unsignedSignature = [signature mutableCopy];
    [unsignedSignature removeObjectForKey: @"sig"];
    return [self verifySignature: *(const CBSignature*)sigData.bytes
                          ofData: [CanonicalJSON canonicalData: unsignedSignature]];
}

/** Verifies a signed JSON object created by +addSignatureToJSON:. */
- (BOOL) verifySignedJSON: (NSDictionary*)jsonDict {
    NSDictionary *signature = [[self class] signatureFromJSON: jsonDict];
    if (!signature)
        return NO;
    NSMutableDictionary *unsignedDict = [jsonDict mutableCopy];
    [unsignedDict removeObjectForKey: kJSONSignatureProperty];
    BOOL valid = [self verifySignature: signature ofJSON: unsignedDict];
    return valid;
}


+ (CBPublicKey*) signerOfJSON:(NSDictionary*)jsonDict {
    CBPublicKey* key = [self keyFromSignature: [self signatureFromJSON: jsonDict]];
    if ([key verifySignedJSON: jsonDict])
        return key;
    return nil;
}

+ (CBPublicKey*) signerOfSignature: (NSDictionary*)signature ofJSON: (id)jsonObject {
    CBPublicKey* key = [self keyFromSignature: signature];
    if ([key verifySignature: signature ofJSON: jsonObject])
        return key;
    return nil;
}


@end




@implementation CBPrivateKey (JSON)

- (NSDictionary*) signatureOfJSON: (id)jsonObject
                        expiresAt: (NSDate*)expires
{
    NSString* keyStr = [self.publicKey.keyData base64EncodedStringWithOptions: 0];
    NSMutableDictionary* signature = [NSMutableDictionary dictionaryWithObjectsAndKeys:
        @[@"SHA1", CanonicalDigestString(jsonObject)], @"digest",
        @[kKeyType, keyStr], @"key",
        formatDate([NSDate date]), @"date",
        nil];
    if (expires) {
        SInt64 expiration = (SInt64)floor(expires.timeIntervalSinceNow / kExpiresUnit);
        if (expiration == 0)
            expiration = 1;
        signature[@"expires"] = @(expiration);
    }
    CBSignature sig = [self sign: [CanonicalJSON canonicalData: signature]];
    NSData* sigData = [NSData dataWithBytes: &sig length: sizeof(sig)];
    signature[@"sig"] = [sigData base64EncodedStringWithOptions: 0];
    return [signature copy];
}


- (NSDictionary*) addSignatureToJSON: (NSDictionary*)jsonDict
                           expiresAt: (NSDate*)expires
{
    NSMutableDictionary *signedDict = [jsonDict mutableCopy];
    [signedDict removeObjectForKey: kJSONSignatureProperty];
    NSDictionary *signature = [self signatureOfJSON: signedDict expiresAt: expires];
    if (!signature)
        return nil;
    signedDict[kJSONSignatureProperty] = signature;
    return signedDict;
}

@end
