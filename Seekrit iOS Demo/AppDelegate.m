//
//  AppDelegate.m
//  Seekrit iOS Demo
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "AppDelegate.h"
@import AudioToolbox;


@interface AppDelegate ()
@end


@implementation AppDelegate

@synthesize scanController=_scanController;


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Override point for customization after application launch.
    [(id)_scanController addObserver: self forKeyPath: @"scannedString" options: 0 context: NULL];
    return YES;
}

- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object
                        change:(NSDictionary *)change context:(void *)context
{
    if (object == _scanController) {
        [self playShutterSound];
    } else {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
    }
}

- (void) playShutterSound {
    static SystemSoundID sShutterSound;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSURL* url = [[NSBundle mainBundle] URLForResource: @"CameraShutter" withExtension: @"aiff"];
        NSAssert(url, @"Missing audio file");
        AudioServicesCreateSystemSoundID((__bridge CFURLRef)url, &sShutterSound);
    });
    AudioServicesPlayAlertSound(sShutterSound);
}

@end
