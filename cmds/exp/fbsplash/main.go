// Copyright 2019-2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// see the example at https://golang.org/pkg/image/png/#Decode

package main

import (
	"fmt"
	"image/png"
	"os"

	"github.com/u-root/u-root/pkg/fb"
)

func main() {
	imageFile, _ := os.Open("./bootsplash.png")
	defer imageFile.Close()
	img, err := png.Decode(imageFile)
	if err != nil {
		fmt.Println(err)
	}
	err = fb.DrawImageAt(img, 300, 20)
	if err != nil {
		fmt.Println(err)
	}
}
