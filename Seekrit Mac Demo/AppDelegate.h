//
//  AppDelegate.h
//  Seekrit Mac Demo
//
//  Created by Jens Alfke on 3/28/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

@import Cocoa;
@import AVKit;
@class CBQRCodeScannerView;


@interface AppDelegate : NSObject <NSApplicationDelegate, NSTabViewDelegate>
{
    IBOutlet NSTabView* tabView;
    IBOutlet CBQRCodeScannerView* captureView;
    IBOutlet NSImageView* qrDisplayView;
    IBOutlet NSTextField* codeStringLabel;
}

@end

