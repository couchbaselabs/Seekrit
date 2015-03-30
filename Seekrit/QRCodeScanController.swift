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
import AssetsLibrary
import AVFoundation

/** A view controller that uses the device camera to scan for a QR code. */
public class QRCodeScanController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {

    /** This property will be set when a QR code is scanned.
        If a different QR code is scanned later, its value will change. (Observable) */
    public var scannedString: String?

    @IBOutlet weak var previewView: UIView!
    @IBOutlet weak var statusLabel: UILabel!
    @IBOutlet weak var codeStringLabel: UILabel!

    var previewLayer: AVCaptureVideoPreviewLayer!
    var session: AVCaptureSession!

    var sharedAssets: [ALAsset]?

    override public func viewDidAppear(animated: Bool) {
        super.viewDidAppear(animated)

        startCapture()
    }

    override public func viewDidDisappear(animated: Bool) {
        pauseCapture()

        super.viewDidDisappear(animated)
    }

    public func startCapture() {
        if session != nil {
            return
        }
        statusLabel.text = "Activating camera..."
        codeStringLabel.text = nil
        scannedString = nil

        let device = AVCaptureDevice.defaultDeviceWithMediaType(AVMediaTypeVideo)
        if device == nil {
            showAlert("No camera found", title: "")
            return
        }

        var error: NSError?
        let input = AVCaptureDeviceInput.deviceInputWithDevice(device, error: &error)
                                                as! AVCaptureDeviceInput
        if error != nil {
            showAlert("Cannot connect to camera", title: "Error")
            return
        }

        session = AVCaptureSession()
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        output.setMetadataObjectsDelegate(self, queue: dispatch_get_main_queue())
        session.addOutput(output)
        output.metadataObjectTypes = [AVMetadataObjectTypeQRCode]

        previewLayer = AVCaptureVideoPreviewLayer.layerWithSession(session)
                                            as! AVCaptureVideoPreviewLayer
        previewLayer.videoGravity = AVLayerVideoGravityResizeAspectFill
        previewLayer.frame = previewView.bounds
        previewView.layer.addSublayer(previewLayer)

        session.startRunning()
        statusLabel.text = "Looking for a QR code..."
    }

    public func pauseCapture() {
        if session != nil {
            session.stopRunning()
            session = nil
            previewLayer.removeFromSuperlayer()
            previewLayer = nil
            codeStringLabel.text = nil
            statusLabel.text = "Not scanning"
        }
    }

//MARK: - AVCaptureMetadataOutputObjectsDelegate

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
                let transformed = previewLayer.transformedMetadataObjectForMetadataObject(metadata)
                    as! AVMetadataMachineReadableCodeObject
                let str = transformed.stringValue
                if str != scannedString {
                    println("SCANNED: \(str)")
                    statusLabel.text = "Scanned a QR code!"
                    codeStringLabel.text = str
                    scannedString = str
                }
            }
        }
    }

    func showAlert(message: String, title: String) {
        statusLabel.text = message
        UIAlertView(title: title, message: message, delegate: nil, cancelButtonTitle: "OK").show()
    }

}