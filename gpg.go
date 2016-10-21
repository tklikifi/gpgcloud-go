package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/tklikifi/gpgcloud-go/encrypt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// trap_sigint catches Ctrl-C and stores terminal state
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

// ask_passphrase shows the prompt and asks for the passphrase
func ask_passphrase(prompt string) ([]byte, error) {
	fmt.Printf(prompt)
	passphrase, err := terminal.ReadPassword(0)
	fmt.Printf("\n")
	return passphrase, err
}

func calculate_file_hash(filename string) (string, error) {
	hasher := sha256.New()
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func show_sha256_checksums(decrypt bool, input_file string, output_file string) {
	input_type, output_type := "Plaintext", "Encrypted"
	if decrypt {
		input_type, output_type = "Encrypted", "Plaintext"
	}
	// Show SHA256 checksums for input and outout files
	input_hash, err := calculate_file_hash(input_file)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	output_hash, err := calculate_file_hash(output_file)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	fmt.Printf("%s file SHA256: %s %s\n", input_type, input_hash, input_file)
	fmt.Printf("%s file SHA256: %s %s\n", output_type, output_hash, output_file)
}

// main function for gpg encrypt and decrypt tool
func main() {
	// Set log formatting
	log.SetFlags(0)
	log.SetOutput(new(logWriter))

	// Parse command line arguments
	flag.Usage = func() {
		fmt.Printf("Usage: gpg [options]\n\n")
		fmt.Printf("Encrypt and decrypt files using the given GPG keys.\n\n")
		flag.PrintDefaults()
	}
	flag_d := flag.Bool("d", false, "Decrypt file")
	flag_i := flag.String("i", "", "Input file")
	flag_o := flag.String("o", "", "Output file")
	flag_p := flag.String("p", ".gnupg/pubring.gpg", "Public key ring")
	flag_s := flag.String("s", ".gnupg/secring.gpg", "Secret key ring")
	flag_v := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *flag_i == "" {
		log.Fatal("ERROR: Input file not given")
	}
	if *flag_o == "" {
		log.Fatal("ERROR: Output file not given")
	}
	if *flag_p == "" {
		log.Fatal("ERROR: Public key ring file not given")
	}
	if *flag_s == "" {
		log.Fatal("ERROR: Secret key ring file not given")
	}

	// Trap Ctrl-C
	trap_sigint()

	// Open files
	i_f, err := os.Open(*flag_i)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := i_f.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()
	o_f, err := os.Create(*flag_o)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := o_f.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()
	p_f, err := os.Open(*flag_p)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := p_f.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()
	s_f, err := os.Open(*flag_s)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := s_f.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()

	// Create readers and writers
	input := bufio.NewReader(i_f)
	output := bufio.NewWriter(o_f)
	pubring := bufio.NewReader(p_f)
	secring := bufio.NewReader(s_f)

	if *flag_d {
		// Ask for passphrase, do not echo the passphrase
		passphrase, err := ask_passphrase("Passphrase: ")
		if err != nil {
			log.Fatal("ERROR: ", err)
		}
		// Decrypt file data
		if _, err := encrypt.Decrypt(secring, passphrase, input, output); err != nil {
			log.Fatal("ERROR: ", err)
		}
	} else {
		// Encrypt file data
		if _, err := encrypt.Encrypt(pubring, input, output); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}
	if *flag_v {
		show_sha256_checksums(*flag_d, *flag_i, *flag_o)
	}
}
