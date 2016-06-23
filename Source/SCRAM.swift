//
//  SCRAM.swift
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

protocol Proof {

    func bytes() -> [UInt8]
}

extension String: Proof {
    
    func bytes() -> [UInt8] {
        return self.dataDecodingBase64String()!.byteArray()
    }
}

extension Array /** where Generator.Element == UInt8 */{
    
    var proof: String {
        return NSData(bytes: self, length: self.count).base64EncodedString()
    }
}

//- seealso: SCRAM.serverSignatureComputation
protocol ServerSignature {
    
    var value: String { get }
}

func == (lhs: ServerSignature, rhs: ServerSignature) -> Bool {
    return (lhs.value == rhs.value)
}

extension Array: ServerSignature /* where Generator.Element == UInt8 */ {
    
    var value: String {
        return NSData(bytes: self, length: self.count).base64EncodedString()
    }
}

/*
    a GS2 header consisting of a flag indicating whether channel binding is
        * supported-but-not-used,
        * not supported,
        * or used,
    and an optional SASL authorization identity;
*/

enum GS2Header : String, CustomStringConvertible {
    
    case NotSupported = "n,,"
    
    func base64Encoded() -> String {
        return rawValue.stringInbase64Encoding()
    }
    
    var description: String {
        return self.rawValue
    }
}

struct ChannelBinding: CustomStringConvertible {
    
    let gs2Header: GS2Header
    var data: [UInt8]?
    
    var description: String {
        
        switch self.gs2Header {
        case .NotSupported:
        return (self.gs2Header.base64Encoded())
        }
    }
}

typealias SaltedPasswordComputation = (password: String, salt: [UInt8], rounds: UInt32) -> [UInt8]
typealias ClientKeyComputation = (saltedPassword: [UInt8]) -> [UInt8]
typealias StoredKeyComputation = (clientKey: [UInt8]) -> [UInt8]
typealias ClientSignatureComputation = (storedKey: [UInt8], authMessage: AuthMessage) -> [UInt8]
typealias ClientProofComputation = (clientKey: [UInt8], clientSignature: [UInt8]) -> [UInt8]
typealias ServerKeyComputation = (saltedPassword: [UInt8]) -> [UInt8]
typealias ServerSignatureComputation = (serverKey: [UInt8], authMessage: AuthMessage) -> [UInt8]

//- seealso: SCRAM.clientKeyComputation
typealias ClientKey = [UInt8]

//- seealso: SCRAM.storedKeyComputation
typealias StoredKey = [UInt8]

//- seealso: SCRAM.serverKeyComputation
typealias ServerKey = [UInt8]

class SCRAM {
    
    enum Error: ErrorType {
        case ServerKeyMissing
        case ClientNonceMismatch
        case ServerNonceMismatch
        case ClientProofMismatch
        case ServerSignatureMismatch
    }

    static let ChannelBindingNotSupported = ChannelBinding(gs2Header: .NotSupported, data: nil)
    
    /**
     SaltedPassword  := Hi(Normalize(password), salt, i)
     
     - seealso: [SaltedPassword, 3. SCRAM Algorithm Overview, RFC 5802](https://tools.ietf.org/html/rfc5802#section-3)
     */
    static let saltedPasswordComputation: SaltedPasswordComputation = { password, salt, rounds in
        return PBKDF_SHA1(salt: salt, rounds: rounds).hash(private: password)
    }
    
    /**
     ClientKey       := HMAC(SaltedPassword, "Client Key")
     
     - seealso: [ClientKey, 3. SCRAM Algorithm Overview, RFC 5802](https://tools.ietf.org/html/rfc5802#section-3)
     */
    static let clientKeyComputation: ClientKeyComputation = { saltedPassword in
        return CryptographicKey(value: saltedPassword).HMAC_SHA1("Client Key")
    }
    
    /**
     StoredKey       := H(ClientKey)
     
     - seealso: [StoredKey, 3. SCRAM Algorithm Overview, RFC 5802](https://tools.ietf.org/html/rfc5802#section-3)
     */
    static let storedKeyComputation: StoredKeyComputation = { clientKey in
        return CryptographicHashFunctions.SHA1_HASH_FUNCTION.hash(private: clientKey)
    }
    
    /**
     ClientSignature := HMAC(StoredKey, AuthMessage)
     
     - seealso: [ClientSignature, 3. SCRAM Algorithm Overview, RFC 5802](https://tools.ietf.org/html/rfc5802#section-3)
     */
    
    static let clientSignatureComputation: ClientSignatureComputation = { storedKey, authMessage in
        return CryptographicKey(value:storedKey).HMAC_SHA1(authMessage.value)
    }
    
    /**
     ClientProof     := ClientKey XOR ClientSignature
     
     - seealso: [ClientProof, 3. SCRAM Algorithm Overview, RFC 5802](https://tools.ietf.org/html/rfc5802#section-3)
     */
    static let clientProofComputation: ClientProofComputation = { clientKey, clientSignature in
        return try! clientKey ^ clientSignature
    }
    
    /**
     ServerKey       := HMAC(SaltedPassword, "Server Key")
     
     - seealso: [ServerKey, 3. SCRAM Algorithm Overview, RFC 5802](https://tools.ietf.org/html/rfc5802#section-3)
     */
    static let serverKeyComputation: ServerKeyComputation = { saltedPassword in
        return CryptographicKey(value: saltedPassword).HMAC_SHA1("Server Key")
    }
    
    /**
     ServerSignature := HMAC(ServerKey, AuthMessage)
     
     
     - seealso: SCRAMChannel.authMessage(clientFirstMessageBare: serverFirstMessage:)
     */
    static let serverSignatureComputation: ServerSignatureComputation = { serverKey, authMessage in
        return CryptographicKey(value:serverKey).HMAC_SHA1(authMessage.value)
    }
    
    /**
     Create the client first message given a username and a nonce (optional).
     
     - parameters:
     - username: MUST either implement SASLprep or disallow use of non US-ASCII Unicode codepoints.
     - nonce: MUST use printable characters from the ASCII set; must NOT contain the ',' comma character
     
     - note: Default nonce, uses printable characters from the ASCII set, excluding the comma, has length 24.
     - returns: the ClientFirstMessage
     - seealso: ExcludingComma
     - seealso: [client-first-message, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
     */
    static func clientFirstMessage(username username: String, nonce: String = AsciiPrintableCharacterSet.ExcludingComma.generateNonce(length: 24), gs2Header: GS2Header = GS2Header.NotSupported) -> ClientFirstMessage {
        
        let clientFirstMessageBare = "n=\(username),r=\(nonce)"
        let clientFirstMessage = "\(gs2Header)\(clientFirstMessageBare)"
        
        return TextMessage<ClientFirstMessage>(stringLiteral: clientFirstMessage)
    }
    
    /**
     Create the server first message given the client nonce, a salt base64, an iteration count and a nonce (optional).
     
     - parameters:
     - clientNonce: ClientFirstMessage.nonce
     - saltBase64Encoded: MUST be base 64 encoded
     - iterationCount: a positive number
     - nonce: MUST use printable characters from the ASCII set, excluding the comma.
     
     - note: Default nonce, uses printable characters from the ASCII set, excluding the comma, has length 18.
     - returns: the ServerFirstMessage
     - seealso: ExcludingComma
     - seealso: [server-first-message, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
     */
    static func serverFirstMessage(clientNonce clientNonce: String, saltBase64Encoded: String = "QSXCR+Q6sek8bf92", iterationCount: UInt32 = 4096, nonce: String = AsciiPrintableCharacterSet.ExcludingComma.generateNonce(length: 18)) -> ServerFirstMessage {
        
        let serverNonce = "\(clientNonce)\(nonce)"
        let serverFirstMessage = "r=\(serverNonce),s=\(saltBase64Encoded),i=\(iterationCount)"
        
        return TextMessage<ServerFirstMessage>(stringLiteral: serverFirstMessage)
    }
    
    /**
     > AuthMessage     := client-first-message-bare + "," +
     server-first-message + "," +
     client-final-message-without-proof
     
     - parameters:
     - clientFirstMessageBare: ClientFirstMessage.clientFirstMessageBare
     - serverFirstMessage: SCRAM.clientProofComputation
     - seealso: [AuthMessage, 3. SCRAM Algorithm Overview, RFC 5802](https://tools.ietf.org/html/rfc5802#section-3)
     */
    static func authMessage(clientFirstMessageBare clientFirstMessageBare: String, serverFirstMessage: ServerFirstMessage, channelBinding: ChannelBinding = SCRAM.ChannelBindingNotSupported) -> AuthMessage {
        
        let clientFinalMessageWithoutProof = "c=\(channelBinding),r=\(serverFirstMessage.nonce)"
        
        let authMessage = "\(clientFirstMessageBare),\(serverFirstMessage),\(clientFinalMessageWithoutProof)"
        
        return TextMessage<AuthMessage>(stringLiteral: authMessage)
    }
    
    /**
     Create the client final message given the client final message without proof and the client proof
     
     >    client-final-message = client-final-message-without-proof "," proof
     
     - parameters:
     - clientFinalMessageWithoutProof: AuthMessage.clientFinalMessageWithoutProof
     - clientProof: SCRAM.clientProofComputation
     - seealso: [client-final-message, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
     */
    static func clientFinalMessage(clientFinalMessageWithoutProof: String, clientProof: [UInt8]) -> ClientFinalMessage {
        
        let clientFinalMessage = "\(clientFinalMessageWithoutProof),p=\(clientProof.proof)"
        
        return TextMessage<ClientFinalMessage>(stringLiteral: clientFinalMessage)
    }
    
    /**
     Create the server final message given the server signature
     
     >    server-final-message = (server-error / verifier) ["," extensions]

     
     - parameters:
     - serverSignature: SCRAM.serverSignatureComputation
     - returns: the ServerFinalMessage
     - seealso: [server-final-message, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
     */
    static func serverFinalMessage(serverSignature: ServerSignature) -> ServerFinalMessage {
        return TextMessage<ServerFinalMessage>(stringLiteral: "v=\(serverSignature.value)")
    }
}