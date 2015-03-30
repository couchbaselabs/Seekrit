//
//  CBQRCodeScannerView.m
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBQRCodeScannerView.h"
@import AVFoundation;
@import AVKit;


@interface CBQRCodeScannerView () <AVCaptureVideoDataOutputSampleBufferDelegate>
@property (readwrite) NSString* scannedString;
@property (readwrite) NSError* error;
@end


@implementation CBQRCodeScannerView
{
    IBOutlet AVCaptureView* _captureView;
    CIDetector* _qrDetector;
}

@synthesize scannedString=_scannedString;


- (void) drawRect:(NSRect)dirtyRect {
    [[NSColor blackColor] set];
    NSFrameRect(self.bounds);
}


- (void) startCapture {
    if (self.isHiddenOrHasHiddenAncestor)
        return;
    if (!_captureView) {
        NSLog(@"Starting video capture...");
        AVCaptureSession* session = [[AVCaptureSession alloc] init];
        AVCaptureDevice* video = [AVCaptureDevice defaultDeviceWithMediaType: AVMediaTypeVideo];
        if (!video) {
            NSString* message = @"No video camera available";
            self.error = [NSError errorWithDomain: @"CBQRCodeScannerView"
                                             code: 1
                                         userInfo: @{NSLocalizedFailureReasonErrorKey: message}];
        }
        NSError* error;
        AVCaptureDeviceInput* input = [AVCaptureDeviceInput deviceInputWithDevice: video
                                                                            error: &error];
        if (!input) {
            self.error = error;
            return;
        }
        [session addInput: input];

        AVCaptureVideoDataOutput* output = [[AVCaptureVideoDataOutput alloc] init];
        output.alwaysDiscardsLateVideoFrames = YES;
        [output setSampleBufferDelegate: self queue: dispatch_get_main_queue()];
        [session addOutput: output];

        [session startRunning];

        _captureView = [[AVCaptureView alloc] initWithFrame: self.bounds];
        [self addSubview: _captureView];
        [_captureView setSession: session showVideoPreview: YES showAudioPreview: NO];

        // Lower frame rate (has to be done after adding the session to the view)
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
}


- (void) pauseCapture {
    if (_captureView) {
        NSLog(@"Stopping video capture");
        [_captureView removeFromSuperview];
        _captureView = nil;
    }
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
