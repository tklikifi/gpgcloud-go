package encrypt

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"golang.org/x/crypto/openpgp"
	"io"
)

// Encrypt encrypts the data
func Encrypt(pubring *bufio.Reader, input *bufio.Reader, output *bufio.Writer) (string, string, error) {
	// Open public key ring
	entityList, err := openpgp.ReadKeyRing(pubring)
	if err != nil {
		return "", "", err
	}

	// Calculate input file hash
	input_hasher := sha256.New()

	// Calculate output file hash
	output_hasher := sha256.New()
	_output := io.MultiWriter(output, output_hasher)

	// Base64 encoder
	encoder := base64.NewEncoder(base64.StdEncoding, _output)

	// Data encrypter
	encrypter, err := openpgp.Encrypt(encoder, entityList, nil, nil, nil)
	if err != nil {
		return "", "", err
	}

	// Create a buffer
	buf := make([]byte, 1024)
	for {
		// Read a chunk
		n, err := input.Read(buf)
		if err != nil && err != io.EOF {
			return "", "", err
		}

		if n == 0 {
			break
		}

		// Add to hash
		if _, err = input_hasher.Write(buf[:n]); err != nil {
			return "", "", nil
		}

		// Write a chunk
		if _, err = encrypter.Write(buf[:n]); err != nil {
			return "", "", err
		}
	}

	// Close and flush files
	if err = encrypter.Close(); err != nil {
		return "", "", err
	}
	if err = encoder.Close(); err != nil {
		return "", "", err
	}
	if err = output.Flush(); err != nil {
		return "", "", err
	}

	return hex.EncodeToString(input_hasher.Sum(nil)), hex.EncodeToString(output_hasher.Sum(nil)), nil
}

// Decrypt decrypts the data
func Decrypt(secring *bufio.Reader, passphrase []byte, input *bufio.Reader, output *bufio.Writer) (string, string, error) {
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the secret key file
	entityList, err := openpgp.ReadKeyRing(secring)
	if err != nil {
		return "", "", err
	}
	entity = entityList[0]

	entity.PrivateKey.Decrypt(passphrase)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphrase)
	}

	// Calculate input file hash
	input_hasher := sha256.New()
	_input := io.TeeReader(input, input_hasher)

	// Base64 decoder
	decoder := base64.NewDecoder(base64.StdEncoding, _input)

	// Data decrypter
	decrypter, err := openpgp.ReadMessage(decoder, entityList, nil, nil)
	if err != nil {
		return "", "", err
	}

	// Calculate output file hash
	output_hasher := sha256.New()
	_output := io.MultiWriter(output, output_hasher)

	// Create a buffer
	buf := make([]byte, 1024)
	for {
		// Read a chunk
		n, err := decrypter.UnverifiedBody.Read(buf)
		if err != nil && err != io.EOF {
			return "", "", err
		}

		if n == 0 {
			break
		}

		// Write a chunk
		if _, err = _output.Write(buf[:n]); err != nil {
			return "", "", err
		}
	}

	// Close and flush files
	if err = output.Flush(); err != nil {
		return "", "", err
	}

	return hex.EncodeToString(input_hasher.Sum(nil)), hex.EncodeToString(output_hasher.Sum(nil)), nil
}
