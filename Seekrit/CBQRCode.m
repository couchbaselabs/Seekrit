//
//  CBQRCode.m
//  Seekrit
//
//  Created by Jens Alfke on 3/28/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "CBQRCode.h"
@import QuartzCore;


@implementation CBQRCode

+ (CBImage*) QRCodeImageWithData: (NSData*)data size: (CGFloat)size {
    CIFilter* filter = [CIFilter filterWithName: @"CIQRCodeGenerator"];
    [filter setValue: data forKey: @"inputMessage"];
//  [filter setValue: @"H" forKey: @"inputCorrectionLevel"];
    CIImage* ciImage = filter.outputImage;
    if (!ciImage)
        return nil;

#if TARGET_OS_IPHONE
    UIImage* tinyImage = [[UIImage alloc] initWithCIImage: ciImage];
    if (size <= tinyImage.size.width)
        return tinyImage;

    // Scale image up:
    UIGraphicsBeginImageContext(CGSizeMake(size, size));
    CGContextSetInterpolationQuality(UIGraphicsGetCurrentContext(), kCGInterpolationNone);
    [tinyImage drawInRect: CGRectMake(0, 0, size, size)];
    UIImage* image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return image;

#else
    NSCIImageRep *rep = [NSCIImageRep imageRepWithCIImage: ciImage];
    NSImage* tinyImage = [[NSImage alloc] init];
    [tinyImage addRepresentation: rep];
    if (size <= rep.size.width)
        return tinyImage;

    // Scale image up:
    NSImage* nsImage = [[NSImage alloc] initWithSize: NSMakeSize(size, size)];
    [nsImage lockFocus];
    [NSGraphicsContext currentContext].imageInterpolation = NSImageInterpolationNone;
    [tinyImage drawInRect: NSMakeRect(0, 0, size, size)];
    [nsImage unlockFocus];
    return nsImage;
#endif
}

+ (CBImage*) QRCodeImageWithData: (NSData*)data {
    return [self QRCodeImageWithData: data size: 500];
}

@end
