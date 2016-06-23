//
//  CryptographicHashFunctionsTest.swift
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

/**
    http://stackoverflow.com/questions/32468600/implementing-scram-sha1-client-getting-it-wrong-somewhere
*/
class CryptographicHashFunctionsTest : XCTestCase
{
    func testGivenBase64EncodedSaltAssertBase64HashedPassword()
    {
        let BASE64_ENCODED_SALT = "QSXCR+Q6sek8bf92"
        let saltedPassword = PBKDF_SHA1(saltBase64String: BASE64_ENCODED_SALT, rounds: 4096)!.hash(private: "pencil")
        
        XCTAssertEqual(NSData(bytes: saltedPassword, length: saltedPassword.count).base64EncodedString(), "HZbuOlKbWl+eR8AfIposuKbhX30=")
    }
    
    func testGivenBase64ClientKeyAssertBase64StoredKey()
    {
        let CLIENT_KEY = "4jTEe/bDZpbdbYUrmaqiuiZVVyg="
        let storedKey = try! SHA1().hash(privateBase64String: CLIENT_KEY)!
        
        XCTAssertEqual(NSData(bytes: storedKey, length: storedKey.count).base64EncodedString(), "6dlGYMOdZcOPutkcNY8U2g7vK9Y=")
    }
    
    func testGivenDigestAssertSHA1()
    {
        let hash = SHA1().hash(private: Array("Client Key".utf8))
        
        XCTAssertNotNil(hash)
        XCTAssertEqual(String(hash: hash), "60609ea75acd96cf360e26618518de021ec26e49")
    }    
}
