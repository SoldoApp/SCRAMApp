//
//  SCRAMMessage.swift
//  SCRAMApp
//
//  Copyright © 2016 Soldo LTD. All rights reserved.
//

import Foundation

/**
 A message that is used in SCRAM to perform the authentication
 
 - seealso: ClientFirstMessage
 - seealso: ServerFirstMessage
 - seealso: AuthMessage
 - seealso: ClientFinalMessage
 - seealso: ServerFinalMessage
 */
protocol SCRAMMessage: CustomStringConvertible, CustomDebugStringConvertible {
    
    // The value of the SCRAM message depends on the type of message.
    var value : String { get }
    
    /**
     > "SCRAM is a SASL mechanism whose client response and server challenge messages are text-based messages containing one or more attribute-value pairs separated by commas." - [5.  SCRAM Authentication Exchange](https://tools.ietf.org/html/rfc5802#section-5)
     */
    var components : [String] { get }
}

extension SCRAMMessage
{
    var channelBinding: String {
        return self.components.valueOf("c")!
    }
    
    var description: String {
        return self.value
    }
    
    var debugDescription: String {
        return value
    }
}

class TextMessage<T> : SCRAMMessage, ClientFirstMessage, AuthMessage, ServerFirstMessage, ClientFinalMessage, ServerFinalMessage, StringLiteralConvertible, Equatable, Hashable, CustomStringConvertible, CustomDebugStringConvertible {
    
    typealias UnicodeScalarLiteralType = StringLiteralType
    typealias ExtendedGraphemeClusterLiteralType = StringLiteralType
    
    let value : String
    internal lazy var components : [String] = {
        self.value.componentsSeparatedByString(",")
    }()
    
    var hashValue: Int {
        return self.value.hashValue
    }
    
    required init(unicodeScalarLiteral value: UnicodeScalarLiteralType) {
        self.value = "\(value)"
    }
    
    required init(extendedGraphemeClusterLiteral value: ExtendedGraphemeClusterLiteralType) {
        self.value = value
    }
    
    required init(stringLiteral value: StringLiteralType) {
        self.value = value
    }
}

func ==<T> (lhs: TextMessage<T>, rhs: TextMessage<T>) -> Bool {
    return (lhs.value == rhs.value)
}

func == (lhs: SCRAMMessage, rhs: SCRAMMessage) -> Bool {
    return (lhs.value == rhs.value)
}

func == (lhs: ClientFirstMessage, rhs: ClientFirstMessage) -> Bool {
    return (lhs.value == rhs.value)
}

func == (lhs: AuthMessage, rhs: AuthMessage) -> Bool {
    return (lhs.value == rhs.value)
}

protocol ContainsNonce: SCRAMMessage {
    
}

extension ContainsNonce {
    /**
     
     > "specifies a sequence of random printable ASCII
     characters excluding ',' (which forms the nonce used as input to
     the hash function)."
     
     - seealso: [5.1.  SCRAM Attributes](https://tools.ietf.org/html/rfc5802#section-5.1)
     */
    var nonce : String {
        return self.components.valueOf("r")!
    }
}

// MARK: - SCRAM Messages

/**
 The value of the client-first-message is in the form of
 
 [gs2-header]n=[user],r=[nonce]
 
 e.g.
 "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"
 
 - note: the GS2Header depends on the SCRAMChannel used to construct this client-first-message
 - seealso: SCRAMChannel.clientFirstMessage(username:nonce:) on how to construct the client first message
 */
protocol ClientFirstMessage : SCRAMMessage, ContainsNonce
{
    /**
     Optionally prepared using SASLprep
     
     - note: implementations MUST either implement SASLprep or disallow use of non US-ASCII Unicode codepoints in "str".
     - returns: "n=[saslname]"
     - seealso: [username, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
     - seealso: [Normalize(str), 2.2 Notation, RFC 5802](https://tools.ietf.org/html/rfc5802#section-2.2)
     */
    var username : String { get }
    
    /**
     - returns: "r=[c-nonce]"
     - seealso: [nonce, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
     */
    var nonce : String { get }
    
    /**
     - returns: "n=[saslname,r=[c-nonce]"
     - seealso: [client-first-message-bare, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
     */
    var clientFirstMessageBare : String { get }
}

/**
 The value of the server-first-message is in the form of
 
 r=[nonce],s=[salt],i=[iteration-count]
 
 e.g.
 "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
 
 - seealso: [nonce, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
 - seealso: [server-first-message, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
 
 */
protocol ServerFirstMessage: SCRAMMessage, ContainsNonce {
    
    /**
     - returns: "s=[base64]"
     */
    var salt: String { get }
    var rounds: UInt32 { get }
    
    /**
     - returns: "r=[c-nonce][s-nonce]"
     - seealso: [nonce, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
     */
    var nonce : String { get }
}

/**
 
 "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j"
 
 */
protocol AuthMessage: SCRAMMessage {
    
    var channelBinding: String { get }
    var clientFinalMessageWithoutProof: String { get }
}

/**
 The value of the client-final-message is in the form of
 
 c=[channel-binding],r=[c-nonce][s-nonce],p=[proof]
 
 channel-binding = base64
 proof = base64
 
 e.g.
 "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="

 - seealso: [channel-binding, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
 - seealso: [nonce, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
 - seealso: [proof, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
 - seealso: [client-final-message, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
 
 */
protocol ClientFinalMessage : SCRAMMessage, ContainsNonce {
    
    var channelBinding: String { get }
    var proof: String { get }
    var nonce : String { get }
}

/**
 The value of the server-final-message in the form of
 
 v=[verifier]
 
 verifier = base64

 e.g.
 "v=rmF9pqV8S7suAoZWja4dJRkFsKQ="
 
 - seealso: [server-final-message, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
 */
protocol ServerFinalMessage : SCRAMMessage {
    
    /**
        base-64 encoded ServerSignature.
 
     - seealso: [verifier, 7.  Formal Syntax, RFC 5802](https://tools.ietf.org/html/rfc5802#section-7)
    */
    var serverSignature : String { get }
}

extension ClientFirstMessage {
    
    var username: String {
        return self.components.valueOf("n")!
    }
    
    var clientFirstMessageBare: String {
        return "n=\(self.username),r=\(self.nonce)"
    }
}

extension ServerFirstMessage {
    
    var salt : String {
        return self.components.valueOf("s")!
    }
    
    var rounds : UInt32 {
        return UInt32(self.components.valueOf("i")!)!
    }
}

extension AuthMessage {
    
    var s_nonce : String {
        return self.components.valuesOf("r")!.last!
    }

    var clientFinalMessageWithoutProof: String {
        return "c=\(self.channelBinding),r=\(self.s_nonce)"
    }
}

extension ClientFinalMessage {
    
    var proof : String {
        return self.components.valueOf("p")!
    }
}

extension ServerFinalMessage {
    
    var serverSignature : String {
        return self.components.valueOf("v")!
    }
}