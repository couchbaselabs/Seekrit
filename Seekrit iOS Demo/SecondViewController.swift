//
//  SecondViewController.swift
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

import UIKit
import AudioToolbox


public class SecondViewController: QRCodeScanController {

    override public func startCapture() -> Bool {
        //scanner.cameraPosition = .Front
        return super.startCapture()
    }

    override public var scannedString :String? {
        didSet {
            if scannedString != nil {
                playShutterSound()
            }
        }
    }

    private static var shutterSound :SystemSoundID = {
        let url = NSBundle.mainBundle().URLForResource("CameraShutter", withExtension: "aiff")
        var soundID :SystemSoundID = 0
        AudioServicesCreateSystemSoundID(url as! CFURLRef, &soundID)
        return soundID
    }()

    func playShutterSound() {
        AudioServicesPlayAlertSound(SecondViewController.shutterSound);
    }

}
