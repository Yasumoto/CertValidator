//
//  ViewController.swift
//  CertValidator
//
//  Created by Joseph Smith on 6/22/17.
//  Copyright © 2017 Joseph Smith. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    func checkUrl(url: String) {
        if let serverUrl = URL(string: url) {
            let session = URLSession(configuration: URLSessionConfiguration.default, delegate: URLSessionPinningDelegate(), delegateQueue: nil)
            let request = URLRequest(url: serverUrl)
            let task = session.dataTask(with: request) {
                if let responded = $1 as? HTTPURLResponse {
                    print("\(responded)")
                }
                if let responseError = $2 {
                    print("Error: \(responseError)")
                    print("Code: \(responseError._code)")
                } else if let data = $0 {
                    _ = data.base64EncodedData()
                }
            }
            task.resume()
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        checkUrl(url: "https://www.google.com")
        checkUrl(url: "https://dev6.slack.com")

    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

