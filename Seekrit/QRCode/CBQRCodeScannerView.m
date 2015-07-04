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
    CIImage* _currentFrame;
    CIQRCodeFeature* _currentFeature;
}

@synthesize showPreview=_showPreview, scannedString=_scannedString, error=_error;


- (instancetype) initWithFrame: (NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        _showPreview = YES;
    }
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder
{
    self = [super initWithCoder:coder];
    if (self) {
        _showPreview = YES;
    }
    return self;
}


- (BOOL) startCapture: (NSError**)outError {
    if (!_scanner) {
        _scanner = [[CBQRCodeScanner alloc] init];
        if (![_scanner startCapture: outError]) {
            _scanner = nil;
            return NO;
        }
        [_scanner addObserver: self forKeyPath: @"currentFrame" options: 0 context: NULL];
        [_scanner addObserver: self forKeyPath: @"scannedString" options: 0 context: NULL];
    }
    return YES;
}


- (void) stopCapture {
    if (_scanner) {
        [_scanner removeObserver: self forKeyPath: @"currentFrame"];
        [_scanner removeObserver: self forKeyPath: @"scannedString"];
        [_scanner pauseCapture];
        _scanner = nil;
    }
}


- (void) drawRect: (NSRect)dirtyRect {
    NSRect bounds = self.bounds;
    NSRectFill(bounds);
    [[NSColor blackColor] set];

    if (!_showPreview)
        return;

    // Mirror the image, otherwise it freaks out the user :)
    NSAffineTransform* flip = [NSAffineTransform transform];
    [flip scaleXBy: -1 yBy: 1];
    [flip translateXBy: -bounds.size.width yBy: 0];

    // Scale the frame to fit in the view bounds:
    NSRect src = _currentFrame.extent;
    CGFloat scale = MIN(bounds.size.width/src.size.width,
                        bounds.size.height/src.size.height);
    [flip scaleBy: scale];
    [flip translateXBy: bounds.size.width - (src.size.width * scale)
                   yBy: bounds.size.height - (src.size.height * scale)];
    [flip concat];

    [_currentFrame drawAtPoint: NSZeroPoint fromRect: src
                     operation: NSCompositeSourceOver fraction: 1.0];

    if (_currentFeature) {
        // Draw a rectangle around the scanned code:
        NSBezierPath* outline = [NSBezierPath bezierPath];
        [outline moveToPoint: _currentFeature.topLeft];
        [outline lineToPoint: _currentFeature.topRight];
        [outline lineToPoint: _currentFeature.bottomRight];
        [outline lineToPoint: _currentFeature.bottomLeft];
        [outline closePath];
        outline.lineWidth = 2.0;
        [[NSColor yellowColor] setStroke];
        [outline stroke];
    }
}


- (void)observeValueForKeyPath: (NSString *)keyPath ofObject: (id)object
                        change: (NSDictionary *)change context: (void *)context
{
    if (object == _scanner) {
        if ([keyPath isEqualToString: @"scannedString"]) {
            self.scannedString = _scanner.scannedString;
        } else if ([keyPath isEqualToString: @"currentFrame"]) {
            _currentFrame = _scanner.currentFrame;
            _currentFeature = _scanner.scannedFeature;
            [self setNeedsDisplay: YES];
        }
    } else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}


- (void) dealloc {
    [self stopCapture];
}


@end
