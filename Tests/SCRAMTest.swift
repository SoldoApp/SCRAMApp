//
//  SCRAMTest.swift
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

class SCRAMTest: XCTestCase
{
    func testGivenPasswordAssertStoredKey()
    {
        let password = "pencil"
        
        let saltedPassword = CryptographicHashFunctions.PBKDF_SHA1_HASH_FUNCTION.hash(private: password)
        let clientKey = SCRAM.clientKeyComputation(saltedPassword: saltedPassword)
        let storedKey = SCRAM.storedKeyComputation(clientKey: clientKey)
        
        XCTAssertEqual(NSData(bytes:storedKey, length: storedKey.count).base64EncodedString(), "6dlGYMOdZcOPutkcNY8U2g7vK9Y=")
    }

    func testGivenNotSupportedAssertString() {
        let notSupportedGS2Header = GS2Header.NotSupported
        
        XCTAssertEqual(notSupportedGS2Header.rawValue, "n,,")
    }

    func testGivenNotSupportedAssertBase64Encoding() {
        let base64EncodedNotSupportedGS2Header = GS2Header.NotSupported.base64Encoded()
        
        XCTAssertEqual(base64EncodedNotSupportedGS2Header, "biws")
    }
    
    func testGivenChannelBindingNotSupportedSCRAMAssertChannelBinding()
    {
        let channelBindingNotSupported = SCRAM.ChannelBindingNotSupported
        
        XCTAssertEqual(channelBindingNotSupported.gs2Header, GS2Header.NotSupported)
    }
    
    func testGivenChannelBindingNotSupportAssertClientFirstMessage()
    {
        let clientFirstMessage:SCRAMMessage = SCRAM.clientFirstMessage(username: "user", nonce:"fyko+d2lbbFgONRv9qkxdawL")
        let expected:SCRAMMessage = TextMessage<ClientFirstMessage>(stringLiteral: "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
        
        XCTAssert(clientFirstMessage == expected, clientFirstMessage.value)
    }
    
    func testGivenSubsequentCallsToGenerateClientFirstMessageAssertDifferentNonce()
    {
        let clientFirstMessage = SCRAM.clientFirstMessage(username: "user")
        let anotherClientFirstMessage = SCRAM.clientFirstMessage(username: "user")
        
        XCTAssertNotEqual(clientFirstMessage.nonce, anotherClientFirstMessage.nonce)
    }
    
    func testGivenClientFirstMesssageBareAndServerFirstMessageAssertAuthMesssage()
    {
        let clientFirstMessageBare = "n=user,r=fyko+d2lbbFgONRv9qkxdawL"
        let serverFirstMessage: TextMessage<ServerFirstMessage> = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
        
        let authMessage = SCRAM.authMessage(clientFirstMessageBare: clientFirstMessageBare, serverFirstMessage: serverFirstMessage)
        
        let expected : AuthMessage = TextMessage<AuthMessage>(stringLiteral: "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j")
        
        XCTAssert(authMessage == expected)
        XCTAssertEqual(authMessage.clientFinalMessageWithoutProof, "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j")
    }
    
    func testGivenAuthMessageAssertClientFinalMessageProof()
    {
        let saltedPassword = CryptographicHashFunctions.PBKDF_SHA1_HASH_FUNCTION.hash(private: "pencil")
        let clientKey = SCRAM.clientKeyComputation(saltedPassword: saltedPassword)
        let storedKey = SCRAM.storedKeyComputation(clientKey: clientKey)
        let authMessage: TextMessage<AuthMessage> = "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j"
        
        let clientSignature = SCRAM.clientSignatureComputation(storedKey: storedKey, authMessage: authMessage)
        let clientProof = SCRAM.clientProofComputation(clientKey: clientKey, clientSignature: clientSignature)
        let clientFinalMessage = SCRAM.clientFinalMessage(authMessage.clientFinalMessageWithoutProof, clientProof: clientProof)
        
        XCTAssertEqual(clientFinalMessage.proof, "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
    }
    
    func testGivenServerSignatureAssertServiceFinalMessage()
    {
        let serverFinalMessage = SCRAM.serverFinalMessage("rmF9pqV8S7suAoZWja4dJRkFsKQ=".dataDecodingBase64String()!.byteArray())
        
        XCTAssertEqual(serverFinalMessage.value, "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", serverFinalMessage.value)
        XCTAssertEqual(serverFinalMessage.serverSignature, "rmF9pqV8S7suAoZWja4dJRkFsKQ=", serverFinalMessage.serverSignature)
    }
}
