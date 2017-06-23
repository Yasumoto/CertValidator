//
//  URLSessionPinningDelegate.swift
//  CertValidator
//
//  Created by Joseph Smith on 6/22/17.
//  Copyright © 2017 Joseph Smith. All rights reserved.
//
// Inspired by https://stackoverflow.com/posts/8903088/revisions
//

import Foundation
import Security
/*
func getIssuerName(certificateX509: X509) -> String? {
    let issuer: String
    if let issuerX509Name: X509_NAME = X509_get_issuer_name(certificateX509) {
        let nid = OBJ_txt2nid("O"); // organization
        let index = X509_NAME_get_index_by_NID(issuerX509Name, nid, -1);
            
        let issuerNameEntry: X509_NAME_ENTRY? = X509_NAME_get_entry(issuerX509Name, index)
            
        if issuerNameEntry != nil {
            let issuerNameASN1: ASN1_STRING? = X509_NAME_ENTRY_get_data(issuerNameEntry)
                
            if (issuerNameASN1 != nil) {
                //unsigned char *issuerName = ASN1_STRING_data(issuerNameASN1);
                //issuer = [NSString stringWithUTF8String:(char *)issuerName];
            }
        }
    }
    return issuer
}*/

class URLSessionPinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Swift.Void) {
        
        // Adapted from OWASP https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#iOS
        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                var secresult = SecTrustResultType.invalid
                if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                    let commonName = UnsafeMutablePointer<CFString?>.allocate(capacity: MemoryLayout<String>.size)
                    // defer { CFRelease(commonName) } // Well at least we're supposed to https://developer.apple.com/documentation/security/1394814-seccertificatecopycommonname
                    let commonNameCopyStatus = SecCertificateCopyCommonName(serverCertificate, commonName)
                    if let name = commonName.pointee {
                        print("Common Name: \(name)")
                    }
                    print("Status of getting Common Name: \(commonNameCopyStatus.description)")
                    if let subjectSummary = SecCertificateCopySubjectSummary(serverCertificate) {
                        print("Summary: \(subjectSummary)")
                    }
                    /*
                     var serverCertificateData = SecCertificateCopyData(serverCertificate)
                     if var data = CFDataGetBytePtr(serverCertificateData) {
                        var wat = data
                        let size = CFDataGetLength(serverCertificateData)
                        let certificateOne: X509 = d2i_X509(nil, &wat, size)
                    }*/
                
                    let status = SecTrustEvaluate(serverTrust, &secresult)
                    if(errSecSuccess == status) {
                        completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust: serverTrust))
                        return
                    }
                }
            }
        }
        // Pinning failed
        completionHandler(URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)
    }
}
