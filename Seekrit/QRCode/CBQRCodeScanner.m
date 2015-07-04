//
//  CBQRCodeScanner.m
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBQRCodeScanner.h"
@import AVFoundation;


#define kMinScanInterval 0.2


@interface CBQRCodeScanner () <AVCaptureVideoDataOutputSampleBufferDelegate>
@property (readwrite) CIImage* currentFrame;
@property (readwrite) CIQRCodeFeature* scannedFeature;
@property (readwrite, copy) NSString* scannedString;
@end


@implementation CBQRCodeScanner
{
    CIDetector* _qrDetector;
    CFAbsoluteTime _lastScanTime;
}

@synthesize captureSession=_session, currentFrame=_currentFrame;


- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver: self];
}


- (BOOL) startCapture: (NSError**)outError {
    if (!_session) {
        _session = [[AVCaptureSession alloc] init];
        AVCaptureDevice* video = [AVCaptureDevice defaultDeviceWithMediaType: AVMediaTypeVideo];
        if (!video)
            return [self failWithMessage: @"No video camera available" error: outError];
        AVCaptureDeviceInput* input = [AVCaptureDeviceInput deviceInputWithDevice: video
                                                                            error: outError];
        if (!input)
            return [self failWithMessage: @"Couldn't acquire input device" error: outError];
        [_session addInput: input];

        AVCaptureVideoDataOutput* output = [[AVCaptureVideoDataOutput alloc] init];
        output.alwaysDiscardsLateVideoFrames = YES;
        [output setSampleBufferDelegate: self queue: dispatch_get_main_queue()];
        [_session addOutput: output];

        NSLog(@"Starting video capture...");
        [[NSNotificationCenter defaultCenter] addObserver: self
                                                 selector: @selector(sessionNotification:)
                                                     name: nil // all notifications
                                                   object: _session];
        [_session startRunning];
    }
    if (!_qrDetector) {
        _qrDetector = [CIDetector detectorOfType: CIDetectorTypeQRCode
                                         context: nil
                                         options: nil];
    }
    return YES;
}


- (BOOL) failWithMessage: (NSString*)message error: (NSError**)outError {
    if (outError) {
        *outError = [NSError errorWithDomain: @"CBQRCodeScannerView"
                                        code: 1
                                    userInfo: @{NSLocalizedFailureReasonErrorKey: message}];
    }
    return NO;
}


- (void) pauseCapture {
    [[NSNotificationCenter defaultCenter] removeObserver: self
                                                    name: nil // all notifications
                                                  object: _session];
    [_session stopRunning];
    _session = nil;
    _qrDetector = nil;
}


- (void) sessionNotification: (NSNotification*)n {
    NSLog(@"Session posted %@", n.name);
}


- (void)captureOutput:(AVCaptureOutput *)captureOutput
didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
       fromConnection:(AVCaptureConnection *)connection
{
    CVImageBufferRef imageBuf = CMSampleBufferGetImageBuffer(sampleBuffer);
    CIImage* frame = [CIImage imageWithCVImageBuffer: imageBuf];
    CFAbsoluteTime time = CFAbsoluteTimeGetCurrent();
    if (time - _lastScanTime >= kMinScanInterval) {
        _lastScanTime = time;
        self.scannedFeature = (CIQRCodeFeature*)[_qrDetector featuresInImage: frame].firstObject;
    }
    self.currentFrame = frame;
    NSString* message = [self.scannedFeature.messageString copy];
    if (message && ![message isEqualToString: _scannedString]) {
        self.scannedString = message;
    }
}


@end
