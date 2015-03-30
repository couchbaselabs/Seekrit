//
//  QRCodeScanController.swift
//  Seekrit
//
//  Created by Jens Alfke on 3/29/15.
//  Copyright (c) 2015 Couchbase. All rights reserved.
//
//  Based on SendViewController by Pasin Suriyentrakorn
//

import UIKit
import AVFoundation


/** A view controller that uses the device camera to scan for a QR code. */
public class QRCodeScanController: UIViewController {

    /** This property will be set when a QR code is scanned.
        If a different QR code is scanned later, its value will change. (Observable) */
    public var scannedString: String?

    @IBOutlet weak var previewView: UIView!
    @IBOutlet weak var statusLabel: UILabel!
    @IBOutlet weak var codeStringLabel: UILabel!

    let scanner = QRCodeScanner()

    var previewLayer: AVCaptureVideoPreviewLayer!


    override public func viewDidAppear(animated: Bool) {
        super.viewDidAppear(animated)
        startCapture()
    }

    override public func viewDidDisappear(animated: Bool) {
        pauseCapture()
        super.viewDidDisappear(animated)
    }

    public func startCapture() -> Bool {
        if previewLayer != nil {
            return true
        }
        statusLabel.text = "Activating camera..."
        codeStringLabel.text = nil
        scannedString = nil

        var error: NSError?
        if !scanner.startCapture(&error) {
            let message = error?.localizedFailureReason ?? "An error occurred."
            statusLabel.text = message
            showAlert(message, title: "Error")
            return false
        }

        previewLayer = AVCaptureVideoPreviewLayer.layerWithSession(scanner.session)
                                            as! AVCaptureVideoPreviewLayer
        previewLayer.videoGravity = AVLayerVideoGravityResizeAspectFill
        previewLayer.frame = previewView.bounds
        previewView.layer.addSublayer(previewLayer)

        scanner.addObserver(self, forKeyPath: "scannedString",
            options: NSKeyValueObservingOptions(0), context: nil)

        statusLabel.text = "Looking for a QR code..."
        return true
    }

    public func pauseCapture() {
        if previewLayer != nil {
            scanner.removeObserver(self, forKeyPath: "scannedString")
            scanner.pauseCapture()
            previewLayer.removeFromSuperlayer()
            previewLayer = nil
            codeStringLabel.text = nil
            statusLabel.text = "Not scanning"
        }
    }

    public override func observeValueForKeyPath(keyPath: String,
                                                ofObject object: AnyObject,
                                                change: [NSObject : AnyObject],
                                                context: UnsafeMutablePointer<Void>)
    {
        if object as! NSObject == scanner {
            scannedString = scanner.scannedString
            codeStringLabel.text = scannedString
            statusLabel.text = "Scanned a QR code!"
        } else {
            super.observeValueForKeyPath(keyPath, ofObject: object, change: change, context: context)
        }
    }

    func showAlert(message: String, title: String = "") {
        statusLabel.text = message
        UIAlertView(title: title, message: message, delegate: nil, cancelButtonTitle: "OK").show()
    }

}