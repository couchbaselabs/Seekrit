//
//  CBQRCodeScannerView.h
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Cocoa/Cocoa.h>


/** A QR-code scanner that uses the camera. The view displays a preview. */
@interface CBQRCodeScannerView : NSView

- (void) startCapture;
- (void) pauseCapture;

/** This property will be set when a QR code is scanned.
    If a different QR code is scanned later, its value will change. (Observable) */
@property (readonly) NSString* scannedString;

/** Error, set if there's a problem connecting to a camera. (Observable) */
@property (readonly) NSError* error;

@end
