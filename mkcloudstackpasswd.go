package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/pbkdf2"
)

const (
	iter    = 100000
	keyLen  = 64
	saltLen = 64
)

func main() {

	pass, err := passwordPrompt()
	if err != nil {
		fatal("password error: %s\n")
	}

	salt, err := makeSalt()
	if err != nil {
		fatal("error generating salt: %s\n", err)
	}

	k := pbkdf2.Key([]byte(pass), salt, iter, keyLen, sha1.New)

	fmt.Printf("%s:%s:%d\n",
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(k),
		iter,
	)

}

func fatal(template string, args ...interface{}) {
	io.WriteString(os.Stderr, fmt.Sprintf(template, args...))
	os.Exit(1)
}

// read password from stdin -- thanks @ahurt!
func passwordPrompt() (string, error) {
	var p1, p2 []byte // passwords
	var err error     // error holder

	// loop until match
	for {
		// prompt user and read password
		fmt.Print("Password: ")
		if p1, err = gopass.GetPasswdMasked(); err != nil {
			return "", err
		}

		// prompt user and read confirmation
		fmt.Print("Confirm:  ")
		if p2, err = gopass.GetPasswdMasked(); err != nil {
			return "", err
		}

		// compare passwords and ensure non-nil
		if bytes.Equal(p1, p2) && p1 != nil {
			// return password string - no error
			return string(p1), nil
		}

		// not equal - try again
		fmt.Print("Password confirmation failed.  Please try again.\n")
	}
}

func makeSalt() ([]byte, error) {
	buf := make([]byte, saltLen)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
