    //
//  ViewController.swift
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

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var usernameTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    @IBOutlet weak var label: UILabel!
    
    let server = Server()
    lazy var client: Client = Client(server: self.server)
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.server.register(self.usernameTextField.text!, password: self.passwordTextField.text!)
    }

    @IBAction func didEnterUsername(usernameTextField: UITextField) {
        self.server.register(usernameTextField.text!, password: self.passwordTextField.text!)
    }

    @IBAction func didTouchUpInsideAuthenticate(sender: UIButton) {
        let username = self.usernameTextField.text!
        let password = self.passwordTextField.text!
        
        do {
            try self.client.authenticate(username, password: password){
                print("authentication successful")
                self.label.text = "Succesfuly authenticated user: '\(username)' using password: '\(password)'"
            }
        }
        catch {
            self.label.text = "Failed to authenticate user: '\(username)' using password: '\(password)'"
        }
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

