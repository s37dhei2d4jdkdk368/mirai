



package server

import "io"



type DriverFactory interface {
	NewDriver() (Driver, error)
}




type Driver interface {
	
	Init(*Conn)

	
	
	
	
	Stat(string) (FileInfo, error)

	
	
	
	ChangeDir(string) error

	
	
	
	ListDir(string, func(FileInfo) error) error

	
	
	DeleteDir(string) error

	
	
	DeleteFile(string) error

	
	
	Rename(string, string) error

	
	
	MakeDir(string) error

	
	
	GetFile(string, int64) (int64, io.ReadCloser, error)

	
	
	PutFile(string, io.Reader, bool) (int64, error)
}
