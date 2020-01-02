// Copyright 2019-2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fb

var digits = [][28]int{
	{
		0, 1, 1, 0,
		1, 0, 0, 1,
		1, 0, 0, 1,
		1, 0, 0, 1,
		1, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 0,
	},
	{
		0, 0, 1, 0,
		0, 1, 1, 0,
		1, 0, 1, 0,
		0, 0, 1, 0,
		0, 0, 1, 0,
		0, 0, 1, 0,
		0, 1, 1, 1,
	},
	{
		0, 1, 1, 0,
		1, 0, 0, 1,
		0, 0, 0, 1,
		0, 0, 1, 0,
		0, 1, 0, 0,
		1, 0, 0, 0,
		1, 1, 1, 1,
	},
	{
		0, 1, 1, 0,
		1, 0, 0, 1,
		0, 0, 0, 1,
		0, 1, 1, 0,
		0, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 0,
	},
	{
		1, 0, 0, 1,
		1, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 1,
		0, 0, 0, 1,
		0, 0, 0, 1,
		0, 0, 0, 1,
	},
	{
		1, 1, 1, 1,
		1, 0, 0, 0,
		1, 1, 1, 0,
		0, 0, 0, 1,
		0, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 0,
	},
	{
		0, 1, 1, 0,
		1, 0, 0, 1,
		1, 0, 0, 0,
		1, 1, 1, 0,
		1, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 0,
	},
	{
		1, 1, 1, 1,
		0, 0, 0, 1,
		0, 0, 0, 1,
		0, 0, 1, 0,
		0, 0, 1, 0,
		0, 1, 0, 0,
		0, 1, 0, 0,
	},
	{
		0, 1, 1, 0,
		1, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 0,
		1, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 0,
	},
	{
		0, 1, 1, 0,
		1, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 1,
		0, 0, 0, 1,
		1, 0, 0, 1,
		0, 1, 1, 0,
	},
}

func DrawDigitAt(
	buf []byte,
	digit int,
	posx int,
	posy int,
	stride int,
	bpp int,
	size int,
) {
	// just green digits :)
	var r byte = 0x70
	var g byte = 0xC0
	var b byte = 0x70
	// iterate over bytes in digits, 4x7
	for x := 0; x < 4; x++ {
		for y := 0; y < 7; y++ {
			if digits[digit][x+y*4] == 1 {
				// iterate for scale factor
				for sx := 1; sx <= size; sx++ {
					for sy := 1; sy <= size; sy++ {
						offset := bpp * ((posy+y*size+sy)*stride + posx + x*size + sx)
						buf[offset+0] = b
						buf[offset+1] = g
						buf[offset+2] = r
					}
				}
			}
		}
	}
}
