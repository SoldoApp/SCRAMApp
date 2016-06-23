//
//  Client.swift
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

class Client
{
    let server: Server
    
    init(server: Server){
        self.server = server
    }
    
    //Note that both the username and the password MUST be encoded in UTF-8 [RFC3629].
    //https://tools.ietf.org/html/rfc5802#section-3
    func authenticate(username: String, password: String, success: () -> Void) throws
    {
        let clientFirstMessage = SCRAM.clientFirstMessage(username: username)
        
        let serverFirstMessage = server.clientFirstMessage(clientFirstMessage)

        let nonce = serverFirstMessage.nonce

        guard nonce.containsString(clientFirstMessage.nonce) else {
            debugPrint("ERROR: The client MUST verify that the initial part of the nonce used in subsequent messages is the same as the nonce it initially specified. Ref: 5.1.  SCRAM Attributes, https://tools.ietf.org/html/rfc5802#section-5.1")
            throw SCRAM.Error.ServerNonceMismatch
        }
        
        let salt = serverFirstMessage.salt
        let rounds = serverFirstMessage.rounds
        let saltedPassword = SCRAM.saltedPasswordComputation(password: password, salt: salt.dataDecodingBase64String()!.byteArray(), rounds: rounds)
        let clientKey = SCRAM.clientKeyComputation(saltedPassword: saltedPassword)
        let storedKey = SCRAM.storedKeyComputation(clientKey: clientKey)
        
        let authMessage = SCRAM.authMessage(clientFirstMessageBare: clientFirstMessage.clientFirstMessageBare, serverFirstMessage: serverFirstMessage)
        let clientSignature = SCRAM.clientSignatureComputation(storedKey: storedKey, authMessage: authMessage)
        let clientProof = SCRAM.clientProofComputation(clientKey: clientKey, clientSignature: clientSignature)
        let clientFinalMessage = SCRAM.clientFinalMessage(authMessage.clientFinalMessageWithoutProof, clientProof: clientProof)
        
        let serverFinalMessage = try self.server.clientFinalMessage(clientFinalMessage)
            
        let serverKey = SCRAM.serverKeyComputation(saltedPassword: saltedPassword)
        let serverSignature = SCRAM.serverSignatureComputation(serverKey: serverKey, authMessage: authMessage)

        guard serverSignature.value == serverFinalMessage.serverSignature else {
            debugPrint("ERROR: The client then authenticates the server by computing the ServerSignature and comparing it to the value sent by the server.  If the two are different, the client MUST consider the authentication exchange to be unsuccessful, and it might have to drop the connection. Ref: 5.  SCRAM Authentication Exchange, https://tools.ietf.org/html/rfc5802#section-5")
            throw SCRAM.Error.ServerSignatureMismatch
        }
        
        success()
    }
}
