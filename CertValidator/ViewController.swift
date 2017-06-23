//
//  ViewController.swift
//  CertValidator
//
//  Created by Joseph Smith on 6/22/17.
//  Copyright © 2017 Joseph Smith. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    var debug = false
    
    @IBOutlet weak var issuersTextView: UITextView!
    @IBOutlet weak var subjectSummaryLabel: UILabel!
    @IBOutlet weak var commonNameLabel: UILabel!
    
    var sessionDelegate = URLSessionPinningDelegate()
    
    func checkUrl(url: String) {
        if let serverUrl = URL(string: url) {
            let session = URLSession(configuration: URLSessionConfiguration.default, delegate: self.sessionDelegate, delegateQueue: nil)
            let request = URLRequest(url: serverUrl)
            let task = session.dataTask(with: request) {
                if let responded = $1 as? HTTPURLResponse {
                    if self.debug {
                        print("\(responded)")
                    }
                }
                if let responseError = $2 {
                    print("Error: \(responseError)")
                    print("Code: \(responseError._code)")
                } else if let data = $0 {
                    if self.debug {
                        print(data.base64EncodedData())
                    }
                }
                DispatchQueue.main.sync {
                    self.commonNameLabel.text = self.sessionDelegate.info?.commonName
                    self.subjectSummaryLabel.text = self.sessionDelegate.info?.subjectSummary
                    self.issuersTextView.text = self.sessionDelegate.info?.issuers?.joined(separator: "\n")
                }
            }
            task.resume()
        }
    }
    @IBAction func enteredHostname(_ sender: UITextField) {
        if let hostname = sender.text {
            if hostname.contains("https://") {
                checkUrl(url: hostname)
            } else {
                checkUrl(url: "https://\(hostname)")
            }
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

