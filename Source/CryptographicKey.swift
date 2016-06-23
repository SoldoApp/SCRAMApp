//
//  CryptographicKey.swift
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
 A byte array representing a cryptographic key
 */
struct CryptographicKey
{
    enum KeyError: ErrorType {
        case SizeNotEqual
    }
    
    let value:[UInt8]
    
    init(value:[UInt8]){
        self.value = value
    }

    init?(valueBase64String value: String) throws {
        guard let value = value.dataDecodingBase64String()?.byteArray() else {
            return nil
        }
        
        self.value = value
    }
    
    /**
     Performs a XOR operation data with the key.
     
     Both "key" and "data" must be of the same size.
     
     Given "key" and "data", the corresponding "hash" is returned by
     XOR(key, data)
     
     Given "key" and "hash", the same "data" is returned
     XOR(key, hash) = data
     
     :param: data a byte array representing the data to be XORed
     :return: a byte array of equal size to the count of the given key after XORing every byte to the byte in same index in data.
     */
    private func XOR(data:[UInt8]) throws -> [UInt8]
    {
        guard data.count == self.value.count else {
            throw KeyError.SizeNotEqual
        }
        
        let count = self.value.count
        var hash = [UInt8](count: count, repeatedValue: 0)
        
        for (index, byte) in self.value.enumerate() {
            hash[index] = byte ^ data[index]
        }
        
        return hash
    }
    
    func hash(data:[UInt8]) throws -> [UInt8] {
        return try self.XOR(data)
    }
    
    func data(hash:[UInt8]) throws -> [UInt8] {
        return try self.XOR(hash)
    }
    
    /**
     :param: data should be UTF8 encoded
     @see Array(String.UTF8View) to convert a String to its array of bytes
     */
    func HMAC_SHA1(data: String) -> [UInt8]
    {
        let sha1hash = [UInt8](count: Int(CC_SHA1_DIGEST_LENGTH), repeatedValue: 0)
        
        CCHmac(UInt32(kCCHmacAlgSHA1),
               self.value, self.value.count,
               data, data.utf8.count,
               UnsafeMutablePointer<UInt8>(sha1hash))
        
        return sha1hash
    }
}

func ^ (key: [UInt8], value: [UInt8]) throws -> [UInt8] {
    return try CryptographicKey(value: key).XOR(value)
}
