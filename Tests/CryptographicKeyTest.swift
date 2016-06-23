//
//  CryptographicKeyTest.swift
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

import XCTest
@testable import SCRAMApp

class CryptographicKeyTest: XCTestCase {

    func testGivenDigestWithKeyAssertHMAC_SHA1()
    {
        let hash = CryptographicKey(value:Array("SaltedPassword".utf8)).HMAC_SHA1("Client Key")
        
        XCTAssertNotNil(hash)
        XCTAssertEqual(String(hash: hash), "6feecd5b5f5fddab06c7c1df448bcba0cf1bc4cd")
    }
    
    func testGivenBase64HashedPasswordAssertBase64ClientKey()
    {
        let BASE_64_HASHED_PASSWORD = "HZbuOlKbWl+eR8AfIposuKbhX30="
        let clientKey = try! CryptographicKey(valueBase64String:BASE_64_HASHED_PASSWORD)!.HMAC_SHA1("Client Key")
        
        XCTAssertEqual(NSData(bytes: clientKey, length: clientKey.count).base64EncodedString(), "4jTEe/bDZpbdbYUrmaqiuiZVVyg=")
    }

    func testGivenBase64HashedPasswordAssertServerKey()
    {
        let BASE_64_HASHED_PASSWORD = "HZbuOlKbWl+eR8AfIposuKbhX30="
        let serverKey = try! CryptographicKey(valueBase64String:BASE_64_HASHED_PASSWORD)!.HMAC_SHA1("Server Key")
        
        XCTAssertEqual(NSData(bytes: serverKey, length: serverKey.count).base64EncodedString(), "D+CSWLOshSulAsxiupA+qs2/fTE=")
    }
    
    func testBase64GivenServerKeyAssertBase64ServerSignature()
    {
        let BASE_64_SERVER_KEY = "D+CSWLOshSulAsxiupA+qs2/fTE="
        let authMessage = "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j"
        
        let serverSignature = try! CryptographicKey(valueBase64String:BASE_64_SERVER_KEY)!.HMAC_SHA1(authMessage)
        
        XCTAssertEqual(NSData(bytes: serverSignature, length: serverSignature.count).base64EncodedString(), "rmF9pqV8S7suAoZWja4dJRkFsKQ=")
    }
    
    func testGivenKeyAndDataAssertHash()
    {
        //10000000 ^ 01111111 = 11111111 = 255
        let key: UInt8 = 128
        let data: UInt8 = 127
        let expected: UInt8 = 255
        
        //key ^ data = hash
        let hash = try! [UInt8](arrayLiteral: key) ^ [UInt8](arrayLiteral: data)
        
        XCTAssertNotNil(hash)
        XCTAssertEqual(hash, [UInt8](arrayLiteral: expected))
        
        //key ^ hash = data
        let actual = try! [UInt8](arrayLiteral: key) ^ hash
        
        XCTAssertNotNil(actual)
        XCTAssertEqual(actual, [UInt8](arrayLiteral: data))
    }    
}
