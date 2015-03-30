//
//  CBQRCodeScanner.m
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBQRCodeScanner.h"
@import AVFoundation;


@interface CBQRCodeScanner () <AVCaptureVideoDataOutputSampleBufferDelegate>
@property (readwrite) NSString* scannedString;
@end


@implementation CBQRCodeScanner
{
    CIDetector* _qrDetector;
}

@synthesize captureSession=_session;


- (BOOL) startCapture: (NSError**)outError {
    if (!_session) {
        NSLog(@"Starting video capture...");
        _session = [[AVCaptureSession alloc] init];
        AVCaptureDevice* video = [AVCaptureDevice defaultDeviceWithMediaType: AVMediaTypeVideo];
        if (!video)
            return [self failWithMessage: @"No video camera available" error: outError];
        NSError* error;
        AVCaptureDeviceInput* input = [AVCaptureDeviceInput deviceInputWithDevice: video
                                                                            error: outError];
        if (!input)
            return NO;

        AVCaptureVideoDataOutput* output = [[AVCaptureVideoDataOutput alloc] init];
        output.alwaysDiscardsLateVideoFrames = YES;
        [output setSampleBufferDelegate: self queue: dispatch_get_main_queue()];
        [_session addOutput: output];

        [_session startRunning];

        // Lower frame rate
        if ([video lockForConfiguration: NULL]) {
            video.activeVideoMinFrameDuration = CMTimeMake(10, 30);  // 3fps
            [video unlockForConfiguration];
        }
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


- (void) setFrameRate: (NSUInteger)frameRate {
    AVCaptureDevice* video = [_session.inputs[0] device];
    if ([video lockForConfiguration: NULL]) {
        video.activeVideoMinFrameDuration = CMTimeMake(30/frameRate, 30);
        [video unlockForConfiguration];
    }
}


- (void) pauseCapture {
    [_session stopRunning];
    _session = nil;
    _qrDetector = nil;
}


- (void)captureOutput:(AVCaptureOutput *)captureOutput
didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
       fromConnection:(AVCaptureConnection *)connection
{
    CVImageBufferRef imageBuf = CMSampleBufferGetImageBuffer(sampleBuffer);
    CIImage* frame = [CIImage imageWithCVImageBuffer: imageBuf];
    CIQRCodeFeature* feature = [_qrDetector featuresInImage: frame].firstObject;
    NSString* message = feature.messageString;
    if (message && ![message isEqualToString: _scannedString]) {
        self.scannedString = message;
    }
}


@end
