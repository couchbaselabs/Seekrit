//
//  QRCodeScanner.swift
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//

import AVFoundation


/** Uses the camera to look for QR codes. */
public class QRCodeScanner: NSObject, AVCaptureMetadataOutputObjectsDelegate {

    /** This property will be set when a QR code is scanned.
        If a different QR code is scanned later, its value will change. (Observable) */
    public dynamic var scannedString: String?

    public var session: AVCaptureSession!


    public func startCapture(error: NSErrorPointer) -> Bool {
        if session != nil {
            return true
        }
        scannedString = nil

        let device = AVCaptureDevice.defaultDeviceWithMediaType(AVMediaTypeVideo)
        if device == nil {
            if error != nil {
                error.memory = NSError(domain: "QRCodeScanner", code: 1,
                                userInfo: [NSLocalizedFailureReasonErrorKey: "No camera available"])
            }
            return false
        }

        let input = AVCaptureDeviceInput.deviceInputWithDevice(device, error: error)
                                                as! AVCaptureDeviceInput?
        if input == nil {
            return false
        }

        session = AVCaptureSession()
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        output.setMetadataObjectsDelegate(self, queue: dispatch_get_main_queue())
        session.addOutput(output)
        output.metadataObjectTypes = [AVMetadataObjectTypeQRCode]

        session.startRunning()
        setFrameRate(3)
        return true
    }

    public func pauseCapture() {
        if session != nil {
            session.stopRunning()
            session = nil
        }
    }

    public func setFrameRate(frameRate: Int) {
        let video = (session.inputs[0] as! AVCaptureDeviceInput).device!
        if (video.lockForConfiguration(nil)) {
            video.activeVideoMinFrameDuration = CMTimeMake(Int64(30/frameRate), Int32(30))
            video.unlockForConfiguration()
        }
    }
    
    public func captureOutput(captureOutput: AVCaptureOutput!,
                              didOutputMetadataObjects metadataObjects: [AnyObject]!,
                              fromConnection connection: AVCaptureConnection!)
    {
        if session == nil {
            // Workaround for iOS7 bugs
            return
        }

        for metadata in metadataObjects as! [AVMetadataObject] {
            if metadata.type == AVMetadataObjectTypeQRCode {
                let transformed = metadata as! AVMetadataMachineReadableCodeObject
                let str = transformed.stringValue
                if str != scannedString {
                    println("SCANNED: \(str)") //TEMP
                    scannedString = str
                }
            }
        }
    }

}
