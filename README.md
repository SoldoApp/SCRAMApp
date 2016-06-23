The SCRAMApp is an iOS application that uses SCRAM (aka [rfc5802](https://tools.ietf.org/html/rfc5802)) to demonstrate the use of SCRAM to authenticate. It includes an implementation of the Salted Challenge Response Authentication Mechanism written in Swift.

Since this is an app, the SCRAM implementation cannot be easily reused from another application. 

Please see the TODO below on what it takes to create SCRAM as a Swift framework. Pull requests are welcomed.


# FEATURES

*  Support of a SCRAM-SHA-1 authentication exchange without the use of channel binding

# TODO

* Support channel binding
* Create test cases that use both usernames and passwords with non-ASCII codepoints.  

>    Informative Note: Implementors are encouraged to create test cases
   that use both usernames and passwords with non-ASCII codepoints.  In
   particular, it's useful to test codepoints whose "Unicode
   Normalization Form C" and "Unicode Normalization Form KC" are
   different.  Some examples of such codepoints include Vulgar Fraction
   One Half (U+00BD) and Acute Accent (U+00B4).
 
See [3: SCRAM Algorithm Overview](https://tools.ietf.org/html/rfc5802#section-3)

# Note

> Before sending the username to the server, the client SHOULD
         prepare the username using the "SASLprep" profile [RFC4013] of
         the "stringprep" algorithm [RFC3454] treating it as a query
         string (i.e., unassigned Unicode code points are allowed).  If
         the preparation of the username fails or results in an empty
         string, the client SHOULD abort the authentication exchange
         (*).

See [5.1.  SCRAM Attributes](https://tools.ietf.org/html/rfc5802#section-5.1)


# Future Work

* Create a Swift framework. See [Adding CommonCrypto to custom Swift framework
](https://forums.developer.apple.com/thread/46477) and [CommonCrypto lacks module definiton
](http://www.openradar.me/18256932)
* An Alamofire component library that supports SCRAM over HTTP.

# Requirements

iOS 8.4  
Xcode 7.3.1

# License

The MIT License (MIT)
Copyright (c) 2016 Soldo LTD

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
