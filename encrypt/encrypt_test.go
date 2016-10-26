/* Test encrypt and decrypt functions */

package encrypt_test

import (
	"bufio"
	"fmt"
	"github.com/tklikifi/gpgcloud-go/encrypt"
	"log"
	"os"
	"testing"
)

func TestEncryptDecryptF(t *testing.T) {
	// Hash is calculated using sha256sum binary
	testdata_hash := "962fbfb18614c6f131ab916e4b3acef63b27a4b83d542de5cc6b52b2b945d6c2"

	// Open keyrings
	p_f, err := os.Open("../.gnupg/pubring.gpg")
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := p_f.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()
	s_f, err := os.Open("../.gnupg/secring.gpg")
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := s_f.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()
	pubring := bufio.NewReader(p_f)
	secring := bufio.NewReader(s_f)

	// Open and create test data files
	i_f_1, err := os.Open("testdata.txt")
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := i_f_1.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()
	o_f_1, err := os.Create("encrypted.b64")
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := o_f_1.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
	}()
	input1 := bufio.NewReader(i_f_1)
	output1 := bufio.NewWriter(o_f_1)

	// Encrypt and base64 encode testdata
	input_hash_1, output_hash_1, err := encrypt.Encrypt(pubring, input1, output1)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}

	i_f_2, err := os.Open("encrypted.b64")
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := i_f_2.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
		os.Remove("encrypted.b64")
	}()

	o_f_2, err := os.Create("decrypted.txt")
	if err != nil {
		log.Fatal("ERROR: ", err)
	}
	defer func() {
		if err := o_f_2.Close(); err != nil {
			log.Fatal("ERROR: ", err)
		}
		os.Remove("decrypted.txt")
	}()
	input2 := bufio.NewReader(i_f_2)
	output2 := bufio.NewWriter(o_f_2)

	// Decrypt encrypted data
	input_hash_2, output_hash_2, err := encrypt.Decrypt(secring, []byte("secret"), input2, output2)
	if err != nil {
		log.Fatal("ERROR: ", err)
	}

	// Check hash values
	if input_hash_1 != output_hash_2 {
		log.Fatal("ERROR: input_hash_1 != output_hash_2")
	}
	if input_hash_1 != testdata_hash {
		log.Fatal("ERROR: input_hash_1 != testdata_hash")
	}
	if output_hash_1 != input_hash_2 {
		log.Fatal("ERROR: output_hash_1 != input_hash_2")
	}
	if output_hash_2 != testdata_hash {
		log.Fatal("ERROR: output_hash_2 != testdata_hash")
	}
	fmt.Println("OK")
	// Output: OK
}
