//
//  CanonicalJSON.h
//  People
//
//  Created by Jens Alfke on 8/15/11.
//  Copyright (c) 2011 Couchbase, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

/** Generates a canonical JSON form of an object tree, suitable for signing.
    See algorithm at <http://wiki.apache.org/couchdb/SignedDocuments>. */
@interface CBCanonicalJSON : NSObject

- (id) initWithObject: (id)object;

/** If non-nil, dictionary keys beginning with these prefixes will be ignored.
    Defaults to @"_" and @"(", appropriate for canonicalizing Couch-type documents, to skip the metadata keys like "_rev" and signing-related keys like "(signed)". */
@property (nonatomic, copy) NSArray* ignoreKeyPrefixes;

/** Keys to include even if they begin with the ignorePrefix.
    Defaults to [@"_id"], appropriate for canonicalizing CBLDB documents. */
@property (nonatomic, copy) NSArray* whitelistedKeys;

/** Canonical JSON string from the input object tree.
    This isn't directly useful for tasks like signing or generating digests; you probably want to use .canonicalData instead for that. */
@property (readonly) NSString* canonicalString;

/** Canonical form of UTF-8 encoded JSON data from the input object tree. */
@property (readonly) NSData* canonicalData;


/** Convenience method that instantiates a CanonicalJSON object and uses it to encode the object. */
+ (NSData*) canonicalData: (id)rootObject;

/** Convenience method that instantiates a CanonicalJSON object and uses it to encode the object, returning a string. */
+ (NSString*) canonicalString: (id)rootObject;

@end
