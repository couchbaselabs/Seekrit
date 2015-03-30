//
//  FirstViewController.m
//  Seekrit iOS Demo
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

#import "FirstViewController.h"
#import "AppDelegate.h"
#import "CBKey.h"
#import "SignedJSON.h"
#import "NSData+Mnemonic.h"
#import "CBQRCode.h"


@interface FirstViewController ()
{
    IBOutlet UIImageView* qrDisplayView;
    IBOutlet UILabel* mnemonicLabel;
}
@end


@implementation FirstViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    CBPrivateKey* privKey = ((AppDelegate*)[UIApplication sharedApplication].delegate).privateKey;
    NSDictionary* obj = @{@"name": @"Pushpaw"};
    NSDictionary* s = [privKey addSignatureToJSON: obj expiresAfter: 5*60];
    NSData* json = [NSJSONSerialization dataWithJSONObject: s options: 0 error: nil];
    NSLog(@"\n%@", [[NSString alloc] initWithData: json encoding: NSUTF8StringEncoding]);
    NSLog(@"Displaying QR code of %lu bytes (%lu bits) of data",
          (unsigned long)json.length, (unsigned long)8*json.length);
    UIImage* qrImage = [CBQRCode QRCodeImageWithData: json];
    qrDisplayView.image = qrImage;

    mnemonicLabel.text = [privKey.publicKey.keyData my_mnemonicWithFormat: @"X X X\n"];
    NSLog(@"Mnemonic:\n%@", mnemonicLabel.text);
}

@end
