//
//  AppDelegate.h
//  Seekrit iOS Demo
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import <UIKit/UIKit.h>
@class ScanViewController;

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property IBOutlet ScanViewController* scanController;


@end

