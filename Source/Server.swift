//'
//  Server.swift
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

class Server
{
    let saltBase64Encoded = "QSXCR+Q6sek8bf92"
    let iterations:UInt32 = 4096

    lazy var PBKDF_SHA1_HASH_FUNCTION: PBKDF_SHA1 = {
        return PBKDF_SHA1(salt: self.saltBase64Encoded.dataDecodingBase64String()!.byteArray(), rounds: self.iterations)
    }()
    
    var storedKey: [UInt8]!
    var serverKey: [UInt8]!
    var clientFirstMessageBare: String!
    var serverFirstMessage: ServerFirstMessage!
    
    func register(username: String, password: String)
    {
        print("register user: '\(username)' using password: '\(password)'") //sent in the clear
        let saltedPassword = PBKDF_SHA1_HASH_FUNCTION.hash(private: password) //should the saltedPassword be created by the client and sent later?
        let clientKey = SCRAM.clientKeyComputation(saltedPassword: saltedPassword)
        
        self.storedKey = SCRAM.storedKeyComputation(clientKey: clientKey)
        self.serverKey = SCRAM.serverKeyComputation(saltedPassword: saltedPassword)
    }
    
    /**

     Create the server-first-message given a client-first-messsage.
     
     - parameter clientFirstMessage: in the format of n,,n=[user],r=[nonce]
     - seealso: SCRAMChannel.clientFirstMessage(username:nonce:)
    */
    func clientFirstMessage(clientFirstMessage:ClientFirstMessage) -> ServerFirstMessage
    {
        let serverFirstMessage = SCRAM.serverFirstMessage(clientNonce: clientFirstMessage.nonce, saltBase64Encoded: saltBase64Encoded, iterationCount: iterations)
        
        self.clientFirstMessageBare = clientFirstMessage.clientFirstMessageBare
        self.serverFirstMessage = serverFirstMessage

        return serverFirstMessage
    }
    
    /**
     
     Create the server-final-message given a client-final-messsage.
     
     - parameter clientFinalMessage: in the format of c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
     - seealso: SCRAMChannel.clientFinalMessage(clientFinalMessageWithoutProof:clientProof:)
     */
    func clientFinalMessage(clientFinalMessage:ClientFinalMessage) throws -> ServerFinalMessage
    {
        guard let serverKey = self.serverKey else {
            assertionFailure("Client hasn't registered first, so unable to create server signature required to prove server identity")
            throw SCRAM.Error.ServerKeyMissing
        }
        
        guard self.serverFirstMessage.nonce.containsString(clientFinalMessage.nonce) else {
            debugPrint("ERROR: The server MUST verify that the nonce sent by the client in the second message is the same as the one sent by the server in its first message. Ref: 5.1.  SCRAM Attributes, https://tools.ietf.org/html/rfc5802#section-5.1")
            throw SCRAM.Error.ClientNonceMismatch
        }
        
        let authMessage = SCRAM.authMessage(clientFirstMessageBare: self.clientFirstMessageBare, serverFirstMessage: self.serverFirstMessage)
        
        let clientProof = clientFinalMessage.proof.bytes()
        let clientSignature = SCRAM.clientSignatureComputation(storedKey: self.storedKey, authMessage: authMessage)
        
        let clientKey = try! clientSignature ^ clientProof
        
        guard(self.storedKey == SCRAM.storedKeyComputation(clientKey: clientKey)) else {
            debugPrint("ERROR: The server verifies the nonce and the proof. Ref: 5.1.  SCRAM Attributes, https://tools.ietf.org/html/rfc5802#section-5.1")
            throw SCRAM.Error.ClientProofMismatch
        }
        
        let serverSignature = SCRAM.serverSignatureComputation(serverKey: serverKey, authMessage: authMessage)        
        let serverFinalMessage = SCRAM.serverFinalMessage(serverSignature)

        return serverFinalMessage
    }
    
}
