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

    /** Set this to specify whether to use the front or back camera. */
    public var cameraPosition: AVCaptureDevicePosition = .Unspecified

    /** This property will be set when a QR code is scanned.
        If a different QR code is scanned later, its value will change. (Observable) */
    public dynamic var scannedString: String?

    /** The underlying session object that's reading the video.
        This can be hooked up to a GUI preview (QRCodeScanController does this.) */
    public var session: AVCaptureSession!


    public func startCapture(error: NSErrorPointer) -> Bool {
        if session != nil {
            return true
        }
        scannedString = nil

        let device = chooseInputDevice()
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

        let output = AVCaptureMetadataOutput()
        output.metadataObjectTypes = [AVMetadataObjectTypeQRCode]
        output.setMetadataObjectsDelegate(self, queue: dispatch_get_main_queue())

        session = AVCaptureSession()
        session.addInput(input)
        session.addOutput(output)
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

    private func chooseInputDevice() -> AVCaptureDevice? {
        if cameraPosition == .Unspecified {
            return AVCaptureDevice.defaultDeviceWithMediaType(AVMediaTypeVideo)
        } else {
            let devices = AVCaptureDevice.devicesWithMediaType(AVMediaTypeVideo) as! [AVCaptureDevice]
            return filter(devices, {$0.position == self.cameraPosition}).first
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
            return            // Workaround for iOS7 bug
        }
        if let metadata = filter(metadataObjects as! [AVMetadataObject],
                                 {$0.type == AVMetadataObjectTypeQRCode}).first,
           let qrMeta = metadata as? AVMetadataMachineReadableCodeObject,
           let str = qrMeta.stringValue
        {
            if str != scannedString {
                scannedString = str // this will notify observers
            }
        }
    }

}
