package nsca

import (
	"crypto/cipher"
)

type cfb8 struct {
	b       cipher.Block
	next    []byte
	out     []byte
	decrypt bool
}

func newCFB8(block cipher.Block, iv []byte, decrypt bool) (stream cipher.Stream) {
	cfb8 := new(cfb8)
	cfb8.b = block
	cfb8.next = make([]byte, len(iv))
	cfb8.out = make([]byte, block.BlockSize())
	cfb8.decrypt = decrypt
	copy(cfb8.next, iv)
	stream = cfb8
	return
}

func NewCFB8Encrypter(block cipher.Block, iv []byte) (stream cipher.Stream) {
	return newCFB8(block, iv, false)
}

func NewCFB8Decrypter(block cipher.Block, iv []byte) (stream cipher.Stream) {
	return newCFB8(block, iv, true)
}

func (this *cfb8) XORKeyStream(dst, src []byte) {
	var val byte
	for i := 0; i < len(src); i++ {
		val = src[i]
		copy(this.out, this.next)
		this.b.Encrypt(this.next, this.next)
		val = val ^ this.next[0]
		copy(this.next, this.out[1:])
		if this.decrypt {
			this.next[7] = src[i]
		} else {
			this.next[7] = val
		}
		dst[i] = val
	}
}
