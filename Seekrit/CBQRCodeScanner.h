//
//  CBQRCodeScanner.h
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
@class AVCaptureSession;


/** Uses the camera to look for QR codes. */
@interface CBQRCodeScanner : NSObject

- (BOOL) startCapture: (NSError**)outError;
- (void) pauseCapture;

/** Adjusts the camera frame rate after capturing starts. Should be set to a low value like 3. */
- (void) setFrameRate: (NSUInteger)frameRate;

/** The underlying session object that's reading the video.
    This can be hooked up to an AVCaptureView (CBQRCodeScannerView does this.) */
@property (readonly) AVCaptureSession* captureSession;

/** This property will be set when a QR code is scanned.
    If a different QR code is scanned later, its value will change. (Observable) */
@property (readonly) NSString* scannedString;

@end
