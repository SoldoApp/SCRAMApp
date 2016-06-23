//
//  Common.swift
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

/**
 Comma separated name=value pairs
 
 i.e.
    "n=user,r=fyko+d2lbbFgONRv9qkxdawL"
 
 */
protocol NameValuePair {
    
    var pair : String { get }
    
    func isName(name: String) -> Bool
    
    var value : String { get }
}

extension String {
    
    init(hash: [UInt8])
    {
        let string = NSMutableString()
        for byte in hash {
            string.appendFormat("%02x", byte)
        }
        
        self.init(string)
    }
}

extension String : NameValuePair {
    
    var pair : String {
        return self
    }
    
    func isName(name: String) -> Bool {
        return self.pair.containsString("\(name)=")
    }
    
    var value : String {
        return self.pair.substringFromIndex(self.pair.characters.startIndex.advancedBy(2))
    }
}

extension String {
    
    func stringInbase64Encoding() -> String {
        return self.dataUsingEncoding(NSUTF8StringEncoding)!.base64EncodedString()
    }
    
    /**
     - returns: a data by decoding self as a base64 string or nil if self is not base64 encoded
     */
    func dataDecodingBase64String() -> NSData? {
        return NSData(base64EncodedString: self, options: NSDataBase64DecodingOptions(rawValue: 0))
    }
}

extension Array where Element : NameValuePair {
    
    func valuesOf(name: String) -> [String]? {
        return self.filter { $0.isName(name) }
            .map{ $0.value }
    }
    
    func valueOf(name: String) -> String? {
        return self.filter { $0.isName(name) }
            .map{ $0.value }
            .first
    }
}

extension NSData {
    
    func base64EncodedString() -> String {
        return self.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
    }
    
    func byteArray() -> [UInt8] {
        return Array( UnsafeBufferPointer(start: UnsafePointer<UInt8>(self.bytes), count: self.length) )
    }
}


