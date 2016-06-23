//
//  CryptographicHashFunction.swift
//  SCRAMApp
//
//  Copyright (c) 2016 Soldo LTD
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation

class CryptographicHashFunctions {
    
    static let SHA1_HASH_FUNCTION = SHA1()
    static let PBKDF_SHA1_HASH_FUNCTION:PBKDF_SHA1 = PBKDF_SHA1(saltBase64String: "QSXCR+Q6sek8bf92", rounds: 4096)!
}

// MARK: - CryptographicHashFunctions
protocol CryptographicHashFunction {
    associatedtype Data
    
    func hash(private value: Data) -> [UInt8]
}

struct SHA1: CryptographicHashFunction {
    
    typealias Data = [UInt8]
    
    /**
     - parameter privateBase64String: the value encoded in base64
     - returns: hash of the given value or nil if the given value is not a base64 encoded string
    */
    func hash(privateBase64String value: String) throws -> [UInt8]? {
        guard let data = value.dataDecodingBase64String()?.byteArray() else {
            return nil
        }
        
        return self.hash(private: data)
    }
    
    // :param: value should be UTF8 encoded
    func hash(private value: [UInt8]) -> [UInt8] {
        
        let sha1hash = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
        CC_SHA1(value, UInt32(value.count), UnsafeMutablePointer<UInt8>(sha1hash))
        
        return sha1hash
    }
}

struct PBKDF_SHA1: CryptographicHashFunction {
    
    typealias Data = String
    
    let salt: [UInt8]
    let rounds: UInt32

    /**    
     - parameter salt: the array of bytes for the salt
     - parameter rounds: the rounds for the key derivation function    
    */
    init(salt: [UInt8], rounds: UInt32){
        self.salt = salt
        self.rounds = rounds
    }
    
    /**    
      - parameter salt: the salt encoded in base64
      - parameter rounds: the rounds for the key derivation function     
      - returns: an instance of PBKDF_SHA1 or nil if the given salt is not a base64 encoded string
    */
    init?(saltBase64String salt: String, rounds: UInt32) {
        
        guard let salt = salt.dataDecodingBase64String()?.byteArray() else {
            return nil
        }
        
        self.salt = salt
        self.rounds = rounds
    }
    
    /**
     
     - parameter value the secret to hash
     */
    func hash(private value: String) -> [UInt8]
    {
        let sha1hash = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
        
        CCKeyDerivationPBKDF(
            UInt32(kCCPBKDF2),
            value, value.utf8.count,
            self.salt, self.salt.count,
            UInt32(kCCPRFHmacAlgSHA1), self.rounds,
            UnsafeMutablePointer<UInt8>(sha1hash), Int(CC_SHA1_DIGEST_LENGTH))
        
        return sha1hash
    }
    
}