//
//  SignedJSON.h
//  People
//
//  Created by Jens Alfke on 8/16/11.
//  Copyright (c) 2011 Couchbase, Inc. All rights reserved.
//

#import "CBSigningPrivateKey.h"


// https://github.com/couchbase/couchbase-lite-ios/wiki/Signed-Documents


/** The property name used in a JSON object to hold the signature. Equal to "(signed)". */
extern NSString* const kCBJSONSignatureProperty;


@interface CBVerifyingPublicKey (JSON)

/** Verifies a signed JSON object and returns the signer's key.
    If verification fails (or the object is unsigned) returns nil. */
+ (CBVerifyingPublicKey*) signerOfJSON:(NSDictionary*)jsonDict
                                 error: (NSError**)outError;

/** Verifies a JSON object with an external signature and returns the signer's key.
    If verification fails (or the object is unsigned) returns nil. */
+ (CBVerifyingPublicKey*) signerOfSignature: (NSDictionary*)signature
                                     ofJSON: (id)jsonObject
                                      error: (NSError**)outError;

/** Returns the signature dictionary of a signed JSON object (without verifying it.) */
+ (NSDictionary*) signatureOfJSON: (id)jsonObject;

/** Returns the date a signature was generated. */
+ (NSDate*) dateOfSignature: (NSDictionary*)signature;

/** Returns the date a signature expires.
    If there is no expiration date, returns [NSDate distantFuture]. */
+ (NSDate*) expirationDateOfSignature: (NSDictionary*)signature;

+ (BOOL) isExpiredSignature: (NSDictionary*)signature;

/** Verifies a signature created by +signatureOfJSON. */
- (BOOL) verifySignature: (NSDictionary*)signature
                  ofJSON: (id)jsonObject
                   error: (NSError**)outError;

/** Verifies a signed JSON object created by +addSignatureToJSON:.
    The object must have been signed by the private key matching the receiver.*/
- (BOOL) verifySignedJSON: (NSDictionary*)jsonDict
                    error: (NSError**)outError;

@end


@interface CBSigningPrivateKey (JSON)

/** Returns a dictionary containing a signature of the given object (which must be JSON-encodable).
    If expirationInterval is greater than zero, the signature will be timestamped as losing its
    validity after that interval from now. */
- (NSDictionary*) signatureOfJSON: (id)jsonObject
                     expiresAfter: (NSTimeInterval)expirationInterval;

/** Returns a copy of the dictionary with a signature (generated by -signatureOfJson:) added to it
    under a "(signed)" key.
    If expirationInterval is greater than zero, the signature will be timestamped as losing its
    validity after that interval from now. */
- (NSDictionary*) addSignatureToJSON: (NSDictionary*)jsonDict
                        expiresAfter: (NSTimeInterval)expirationInterval;

@end


extern NSString* const kCBSignedJSONErrorDomain;

enum {
    kCBSignedJSONErrorExpired = 1,
    kCBSignedJSONErrorIncorrectDigest,
    kCBSignedJSONErrorInvalidSignature,
    kCBSignedJSONErrorUnknownSignatureType,
    kCBSignedJSONErrorUnsigned
};
