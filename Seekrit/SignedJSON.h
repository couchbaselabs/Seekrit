//
//  SignedJSON.h
//  People
//
//  Created by Jens Alfke on 8/16/11.
//  Copyright (c) 2011 Couchbase, Inc. All rights reserved.
//

#import "CBKey.h"


// https://github.com/couchbase/couchbase-lite-ios/wiki/Signed-Documents


/** The property name used in a JSON object to hold the signature. Equal to "(signed)". */
extern NSString* const kJSONSignatureProperty;


@interface CBPublicKey (JSON)

/** Verifies a signed JSON object and returns the signer's key.
    If verification fails (or the object is unsigned) returns nil. */
+ (CBPublicKey*) signerOfJSON:(NSDictionary*)jsonDict;

/** Verifies a JSON object with an external signature and returns the signer's key.
    If verification fails (or the object is unsigned) returns nil. */
+ (CBPublicKey*) signerOfSignature: (NSDictionary*)signature
                          ofJSON: (id)jsonObject;

/** Returns the signature dictionary of a signed JSON object (without verifying it.) */
+ (NSDictionary*) signatureOfJSON: (id)jsonObject;

/** Returns the date a signature was generated. */
+ (NSDate*) dateOfSignature: (NSDictionary*)signature;

/** Returns the date a signature expires.
    If there is no*/
+ (NSDate*) expirationDateOfSignature: (NSDictionary*)signature;
+ (BOOL) isExpiredSignature: (NSDictionary*)signature;

/** Verifies a signature created by +signatureOfJSON. */
- (BOOL) verifySignature: (NSDictionary*)signature
                  ofJSON: (id)jsonObject;

/** Verifies a signed JSON object created by +addSignatureToJSON:.
    The object must have been signed by the private key matching the receiver.*/
- (BOOL) verifySignedJSON: (NSDictionary*)jsonDict;

@end


@interface CBPrivateKey (JSON)

/** Returns a dictionary containing a signature of the given object (which must be JSON-encodable). */
- (NSDictionary*) signatureOfJSON: (id)jsonObject
                     expiresAfter: (NSTimeInterval)expirationInterval;

/** Returns a copy of the dictionary with a signature (generated by -signatureOfJson:) added to it under a "(signed)" key. */
- (NSDictionary*) addSignatureToJSON: (NSDictionary*)jsonDict
                        expiresAfter: (NSTimeInterval)expirationInterval;

@end
