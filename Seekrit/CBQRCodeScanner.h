//
//  CBQRCodeScanner.h
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>
@class AVCaptureSession, CIImage, CIQRCodeFeature;


/** Uses the camera to look for QR codes. */
@interface CBQRCodeScanner : NSObject

- (BOOL) startCapture: (NSError**)outError;
- (void) pauseCapture;

/** The underlying session object that's reading the video.
    This can be hooked up to an AVCaptureView (CBQRCodeScannerView does this.) */
@property (readonly) AVCaptureSession* captureSession;

@property (readonly) CIImage* currentFrame;

/** This property will be set when a QR code is scanned.
    If a different QR code is scanned later, its value will change. (Observable) */
@property (readonly, copy) NSString* scannedString;

@property (readonly) CIQRCodeFeature* scannedFeature;

@end
