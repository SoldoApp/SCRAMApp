//
//  AsciiPrintableCharacterSet.swift
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

struct AsciiPrintableCharacterSet : StringLiteralConvertible
{
    /*
    Character '"' (double quote) is escaped by \
    Character '\' (backslash) is escaped by \
    
    Character ',' is excluded
    
    :see: https://en.wikipedia.org/wiki/ASCII#ASCII_printable_code_chart
    */
    static let ExcludingComma = AsciiPrintableCharacterSet(stringLiteral:" !\"#$%&'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~")
    
    typealias UnicodeScalarLiteralType = StringLiteralType
    typealias ExtendedGraphemeClusterLiteralType = StringLiteralType
    
    let value: String
    
    init(unicodeScalarLiteral value: UnicodeScalarLiteralType) {
        self.value = "\(value)"
    }
    
    init(extendedGraphemeClusterLiteral value: ExtendedGraphemeClusterLiteralType) {
        self.value = value
    }
    
    init(stringLiteral value: StringLiteralType) {
        self.value = value
    }
    
    /*
        Generates a nonce. If you want to reuse a nonce, you need to store it.
        Each call generates a new random nonce.
    
        :return: a String of characters meant to be used as a nonce
        :see: https://en.wikipedia.org/wiki/Cryptographic_nonce
    */
    func generateNonce(length length: Int) -> String
    {
        var nonce = String()
        for _ in 0..<length {
            let indexOfRandomCharacter = arc4random_uniform(UInt32(self.value.characters.count))
            let character = self.value.startIndex.advancedBy(Int(indexOfRandomCharacter))
            nonce.append(self.value[character])
        }
        
        return nonce
    }
}
