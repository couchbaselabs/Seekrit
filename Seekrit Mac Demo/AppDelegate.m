//
//  AppDelegate.m
//  Seekrit Mac Demo
//
//  Created by Jens Alfke on 3/28/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "AppDelegate.h"
#import "CBQRCodeScannerView.h"
#import "CBQRCode.h"
#import "CBKey.h"
#import "SignedJSON.h"
@import AVFoundation;


@interface AppDelegate () <AVCaptureVideoDataOutputSampleBufferDelegate>
@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate
{
    CIDetector* _qrDetector;
}


- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    [captureView addObserver: self forKeyPath: @"scannedString" options: 0 context: NULL];

    CBPrivateKey* privKey = [[CBPrivateKey alloc] init];
    NSDictionary* obj = @{@"name": @"Pupshaw"};
    NSDictionary* s = [privKey addSignatureToJSON: obj expiresAfter: 5*60];
    NSData* json = [NSJSONSerialization dataWithJSONObject: s options: 0 error: nil];
    NSLog(@"\n%@", [[NSString alloc] initWithData: json encoding: NSUTF8StringEncoding]);
    NSLog(@"Displaying QR code of %lu bytes (%lu bits) of data", json.length, 8*json.length);
    NSImage* qrImage = [CBQRCode QRCodeImageWithData: json];
    qrDisplayView.image = qrImage;

    [self tabView: tabView didSelectTabViewItem: tabView.selectedTabViewItem];
}


- (void) tabView:(NSTabView *)tabView didSelectTabViewItem:(NSTabViewItem *)tabViewItem {
    if ([tabViewItem.identifier isEqual: @"Scan"]) {
        codeStringLabel.hidden = YES;
        captureView.hidden = NO;
        [captureView performSelector: @selector(startCapture:) withObject: nil afterDelay: 0.1];
    } else {
        [captureView pauseCapture];
    }
}


- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object
                        change:(NSDictionary *)change context:(void *)context
{
    if (object == captureView) {
        NSLog(@"*** Scanned: %@", captureView.scannedString);
        codeStringLabel.stringValue  = captureView.scannedString;
        codeStringLabel.hidden = NO;
        [captureView pauseCapture];
        captureView.hidden = YES;
        [[NSSound soundNamed: @"CameraShutter.aiff"] play];
    } else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}


@end
