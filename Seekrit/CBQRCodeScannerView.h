//
//  CBQRCodeScannerView.h
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Cocoa/Cocoa.h>


/** A view that uses a CBQRCodeScanner and displays a preview of the camera image. */
@interface CBQRCodeScannerView : NSView

- (BOOL) startCapture: (NSError**)outError;
- (void) pauseCapture;

/** This property will be set when a QR code is scanned.
    If a different QR code is scanned later, its value will change. (Observable) */
@property (readonly) NSString* scannedString;

@end
