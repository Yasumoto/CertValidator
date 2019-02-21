//
//  URLSessionPinningDelegate.swift
//  CertValidator
//
//  Created by Joseph Smith on 6/22/17.
//  Copyright © 2017 Joseph Smith. All rights reserved.
//

import Foundation
import Security

struct CertInfo {
    let commonName: String?
    let subjectSummary: String?
    let issuers: [String]?
    let valid: Bool
    let date: Date?
}

class URLSessionPinningDelegate: NSObject, URLSessionDelegate {
    public var info: CertInfo?
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Adapted from OWASP https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#iOS
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            completionHandler(URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)
            return
        }
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)
            return
        }
        var secresult = SecTrustResultType.invalid
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)
            return
        }
        var certCommonName: String? = ""
        var certSubjectSummary: String? = ""
        var issuers = [String]()
        var valid = false
        var date: Date? = nil
        let commonName = UnsafeMutablePointer<CFString?>.allocate(capacity: MemoryLayout<String>.size)
        // defer { CFRelease(commonName) } // Well at least we're supposed to https://developer.apple.com/documentation/security/1394814-seccertificatecopycommonname
        let commonNameCopyStatus = SecCertificateCopyCommonName(serverCertificate, commonName)
        if let name = commonName.pointee {
            print("Common Name: \(name)")
            certCommonName = name as String
        }
        print("Status of getting Common Name: \(commonNameCopyStatus.description)")
        if let subjectSummary = SecCertificateCopySubjectSummary(serverCertificate) {
            print("Summary: \(subjectSummary)")
            certSubjectSummary = subjectSummary as String
        }
        print("Checking issuer sequence")
        if let data = SecCertificateCopyNormalizedIssuerSequence(serverCertificate) {
            if let output = String(data: data as Data, encoding: .utf8) {
                print("Issuers: \(output)")
                issuers = output.components(separatedBy: "\n")
            } else {
                print("Unable to parse issuer")
            }
        }

        let status = SecTrustEvaluate(serverTrust, &secresult)
        if(status == errSecSuccess) {
            valid = true
        }
        self.info = CertInfo(commonName: certCommonName, subjectSummary: certSubjectSummary, issuers: issuers, valid: valid, date: date)
        completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust: serverTrust))

    }
}
