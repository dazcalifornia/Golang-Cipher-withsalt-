package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func main() {
	key := "supersecretkey" // replace this with a secure key in a real-world scenario

	// Read plaintext message from the user
	fmt.Print("Enter a message to encrypt: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	plaintext := scanner.Text()

	salt := generateSalt()

	// Pad the key to the required length
	paddedKey := padKey([]byte(key))

	// Encrypt the message
	encryptedMessage, err := encrypt([]byte(plaintext), paddedKey, salt)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	fmt.Println("Encrypted message:", base64.StdEncoding.EncodeToString(encryptedMessage))

	// Decrypt the message
	decryptedMessage, err := decrypt(encryptedMessage, paddedKey, salt)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted message:", string(decryptedMessage))
}

func generateSalt() []byte {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}
	return salt
}

func padKey(key []byte) []byte {
	desiredKeyLen := 32
	keyLen := len(key)

	if keyLen >= desiredKeyLen {
		return key[:desiredKeyLen]
	}

	paddedKey := make([]byte, desiredKeyLen)
	copy(paddedKey, key)

	return paddedKey
}

func encrypt(plaintext []byte, key []byte, salt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte, salt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}
