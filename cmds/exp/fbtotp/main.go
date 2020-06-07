// Copyright 2019-2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "fmt"
import "github.com/u-root/u-root/pkg/fb"
import "github.com/u-root/tpmtotp/pkg/token"

func main() {
	_, qrCode, _ := token.CreateQRSecretTOTP()
	err := fb.DrawScaledImageAt(qrCode, 100, 60, 3)
	if err != nil {
		fmt.Println(err)
	}
}
