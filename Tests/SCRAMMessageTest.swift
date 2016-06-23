//
//  SCRAMMessageTest.swift
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

class SCRAMMessageTest: XCTestCase {

    func testGivenClientFirstAssertNonce()
    {
        let nonce = "nonce"
        let clientFirst = "n,,n=user,r=\(nonce)"
        
        let clientFirstMessage = TextMessage<ClientFirstMessage>(stringLiteral: clientFirst)
        
        XCTAssertEqual(clientFirstMessage.nonce, nonce)
    }
    
    func testGivenClientFirstWithEmptyNonceAssertNonce()
    {
        let nonce = ""
        let clientFirst = "n,,n=user,r=\(nonce)"
        
        let clientFirstMessage = TextMessage<ClientFirstMessage>(stringLiteral: clientFirst)
        
        XCTAssertEqual(clientFirstMessage.nonce, nonce)
    }
    
    
    func testPerformanceOfNonceGivenClientFirstMesssage()
    {
        self.measureBlock {
            let nonce = "nonce"
            let clientFirst = "n,,n=user,r=\(nonce)"
            
            TextMessage<ClientFirstMessage>(stringLiteral: clientFirst).nonce
        }
    }

    func testGivenClientFirstMessageAssertValues() {

        let clientFirstMessage:ClientFirstMessage = TextMessage<ClientFirstMessage>(stringLiteral:"n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")

        XCTAssertEqual("user", clientFirstMessage.username)
        XCTAssertEqual("fyko+d2lbbFgONRv9qkxdawL", clientFirstMessage.nonce)
        XCTAssertEqual("n=user,r=fyko+d2lbbFgONRv9qkxdawL", clientFirstMessage.clientFirstMessageBare)
        XCTAssertEqual("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", clientFirstMessage.value)
    }
    
    func testGivenServerFirstMessageAssertValues() {
        
        let serverFirstMessage: ServerFirstMessage = TextMessage<ServerFirstMessage>(stringLiteral:"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096")

        
        XCTAssertEqual("fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j", serverFirstMessage.nonce)
        XCTAssertEqual("QSXCR+Q6sek8bf92", serverFirstMessage.salt)
        XCTAssertEqual(4096, serverFirstMessage.rounds)
        XCTAssertEqual("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", serverFirstMessage.value)
    }
    
    func testGivenAuthMessageAssertValues() {
        
        let authMessage : AuthMessage = TextMessage<AuthMessage>(stringLiteral: "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j")
        
        XCTAssertEqual("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j", authMessage.clientFinalMessageWithoutProof)
        XCTAssertEqual("n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j", authMessage.value)
    }
    
    func testGivenClientFinalMessageAssertValues() {
        
        let clientFinalMessage : ClientFinalMessage = TextMessage<ClientFinalMessage>(stringLiteral: "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
        
        XCTAssertEqual("biws", clientFinalMessage.channelBinding)
        XCTAssertEqual("fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j", clientFinalMessage.nonce)
        XCTAssertEqual("v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", clientFinalMessage.proof)
        XCTAssertEqual("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", clientFinalMessage.value)
    }
    
    func testGivenServerFinalMessageAssertValues() {
        
        let serverFinalMessage : ServerFinalMessage = TextMessage<ServerFinalMessage>(stringLiteral: "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=")
        
        XCTAssertEqual("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", serverFinalMessage.value)
        XCTAssertEqual("rmF9pqV8S7suAoZWja4dJRkFsKQ=", serverFinalMessage.serverSignature)        
    }
}
