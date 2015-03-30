//
//  CBQRCodeScannerView.m
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBQRCodeScannerView.h"
#import "CBQRCodeScanner.h"
@import AVFoundation;
@import AVKit;


@interface CBQRCodeScannerView ()
@property (readwrite) NSString* scannedString;
@property (readwrite) NSError* error;
@end


@implementation CBQRCodeScannerView
{
    CBQRCodeScanner* _scanner;
    AVCaptureView* _captureView;
}

@synthesize scannedString=_scannedString, error=_error;


- (void) drawRect:(NSRect)dirtyRect {
    [[NSColor blackColor] set];
    NSFrameRect(self.bounds);
}


- (BOOL) startCapture: (NSError**)outError {
    if (self.isHiddenOrHasHiddenAncestor)
        return YES;
    if (!_captureView) {
        _scanner = [[CBQRCodeScanner alloc] init];
        if (![_scanner startCapture: outError])
            return NO;

        [_scanner addObserver: self forKeyPath: @"scannedString" options: 0 context: NULL];

        _captureView = [[AVCaptureView alloc] initWithFrame: self.bounds];
        [self addSubview: _captureView];
        [_captureView setSession: _scanner.captureSession
                showVideoPreview: YES showAudioPreview: NO];
        [_scanner setFrameRate: 3];
    }
    return YES;
}


- (void) pauseCapture {
    if (_captureView) {
        NSLog(@"Stopping video capture");
        [_captureView removeFromSuperview];
        _captureView = nil;
    }
    if (_scanner) {
        [_scanner removeObserver: self forKeyPath: @"scannedString"];
        [_scanner pauseCapture];
        _scanner = nil;
    }
}


- (void)dealloc {
    [self pauseCapture];
}


- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object
                        change:(NSDictionary *)change context:(void *)context
{
    if (object == _scanner) {
        self.scannedString = _scanner.scannedString;
    } else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}


@end
