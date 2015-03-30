//
//  CBQRCode.h
//  Seekrit
//
//  Created by Jens Alfke on 3/28/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <Foundation/Foundation.h>

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
typedef UIImage CBImage;
#else
#import <AppKit/AppKit.h>
typedef NSImage CBImage;
#endif


@interface CBQRCode : NSObject

/** Returns an image of a QR code with the given data. The image will be 500 pixels on a side. */
+ (CBImage*) QRCodeImageWithData: (NSData*)data;

/** Returns an image of a QR code with the given data. The image will be 'size' pixels on a side. */
+ (CBImage*) QRCodeImageWithData: (NSData*)data
                            size: (CGFloat)size;

@end
