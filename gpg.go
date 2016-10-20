package main

import (
	"bytes"
	"encoding/base64"
    "fmt"
    "flag"
	"golang.org/x/crypto/openpgp"
    "golang.org/x/crypto/ssh/terminal"
    "io/ioutil"
	"log"
	"os"
    "os/signal"
    "syscall"
    "time"
)

func encrypt(pubringFile string, inputFile string, outputFile string) (string, error) {
	// Open files
	pubring, err := os.Open(pubringFile)
    if err != nil {
        return "", err
    }
    defer pubring.Close()
    plaintext, err := ioutil.ReadFile(inputFile)
    if err != nil {
        return "", err
    }
    entityList, err := openpgp.ReadKeyRing(pubring)
	if err != nil {
		return "", err
	}

	// Encrypt data
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write(plaintext)
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	// Encode to base64
    ciphertext, err := ioutil.ReadAll(buf)
    if err != nil {
        return "", err
    }
	ciphertext_b64 := base64.StdEncoding.EncodeToString(ciphertext)

    // Write to file
    err = ioutil.WriteFile(outputFile, []byte(ciphertext_b64), 0644)
    if err != nil {
        return "", err
    }
    return "ok", nil
}

func decrypt(passphrase []byte, secringFile string, inputFile string, outputFile string) (string, error) {
	// Init some variables
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the secret key file
	secring, err := os.Open(secringFile)
	if err != nil {
		return "", err
	}
	defer secring.Close()
	entityList, err = openpgp.ReadKeyRing(secring)
	if err != nil {
		return "", err
	}
	entity = entityList[0]

	entity.PrivateKey.Decrypt(passphrase)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphrase)
	}

    // Read encrypted data
    ciphertext_b64, err := ioutil.ReadFile(inputFile)
    if err != nil {
        return "", err
    }

	// Decode the base64 string
	ciphertext, err := base64.StdEncoding.DecodeString(string(ciphertext_b64))
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(ciphertext), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	plaintext, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}

    // Write to file
    err = ioutil.WriteFile(outputFile, plaintext, 0644)
    if err != nil {
        return "", err
    }
    return "ok", nil
}

func trap_sigint() {
    state, err := terminal.GetState(0)
    if err != nil {
        log.Fatal(err)
    }
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGINT)
    go func() {
        <-c
        terminal.Restore(0, state)
        os.Exit(1)
    }()
}

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
    return fmt.Print("[" + time.Now().Format("2006-01-02T15:04:05.999") + "] " + string(bytes))
}

func main() {
    log.SetFlags(0)
    log.SetOutput(new(logWriter))

    // Parse command line arguments
    flag.Usage = func() {
        fmt.Printf("Usage: gpg [options]\n\n")
        fmt.Printf("Encrypt and decrypt files using the given GPG keyrings.\n\n")
        flag.PrintDefaults()
    }
    d := flag.Bool("d", false, "Decrypt file")
    i := flag.String("i", "", "Input file to read from")
    o := flag.String("o", "", "Output file to write to")
    p := flag.String("p", ".gnupg/pubring.gpg", "Public key ring")
    s := flag.String("s", ".gnupg/secring.gpg", "Secret key ring")
    flag.Parse()

    if *i == "" {
        log.Fatal("ERROR: Input file not given")
    }
    if *o == "" {
        log.Fatal("ERROR: Output file not given")
    }
    if *p == "" {
        log.Fatal("ERROR: Public key ring file not given")
    }
    if *s == "" {
        log.Fatal("ERROR: Secret key ring file not given")
    }

    // Trap Ctrl-C
    trap_sigint()

    if *d == true {
        // Ask for passphrase, do not echo
        fmt.Printf("Passphrase: ")
        passphrase, err := terminal.ReadPassword(0)
        fmt.Printf("\n")
        if err != nil {
            log.Fatal("ERROR: ", err)
        }
        _, err = decrypt(passphrase, *s, *i, *o)
        if err != nil {
            log.Fatal("ERROR: ", err)
        }
    } else {
    	_, err := encrypt(*p, *i, *o)
    	if err != nil {
    		log.Fatal("ERROR: ", err)
    	}
    }
}
