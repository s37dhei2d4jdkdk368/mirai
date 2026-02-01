package ftp

import (
	"cnc/core/frontend/ftp/filedriver"
	server2 "cnc/core/frontend/ftp/server"
)

func Serve(port int) {
	var perm = server2.NewSimplePerm("root", "root")
	opt := &server2.ServerOpts{
		Factory: &filedriver.FileDriverFactory{
			RootPath: "assets/static/",
			Perm:     perm,
		},
		Hostname: "",
		Port:     port,
		Auth:     &server2.NoAuth{},
		Logger:   new(server2.DiscardLogger),
	}

	s := server2.NewServer(opt)
	err := s.ListenAndServe()
	if err != nil {
		return
	}

}
