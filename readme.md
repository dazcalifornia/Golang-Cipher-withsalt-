# Simple AES Encryption and Decryption in Go

This is a basic example of encrypting and decrypting a message using the AES cipher in the Go programming language. The program takes a message from the user, encrypts it, and then decrypts it, displaying the results.

## Prerequisites

Ensure you have Go installed on your system.

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/golang-aes-encryption.git
   Change into the project directory:
   ```

bash

cd golang-aes-encryption
Run the program:

bash

go run main.go
Enter a message when prompted.

The program will display the encrypted and decrypted messages along with the Base64-encoded ciphertext.

Code Explanation
main.go
generateSalt(): Generates a random salt of 16 bytes.

padKey(key []byte) []byte: Pads the given key to ensure its length is exactly 32 bytes.

encrypt(plaintext []byte, key []byte, salt []byte) ([]byte, error): Encrypts the plaintext message using the AES cipher in CFB mode. The key is derived from the provided key and salt.

decrypt(ciphertext []byte, key []byte, salt []byte) ([]byte, error): Decrypts the ciphertext message using the AES cipher in CFB mode. The key is derived from the provided key and salt.

main():

Reads a plaintext message from the user.

Generates a random salt.

Pads the key to ensure it is 32 bytes.

Encrypts the message and displays the Base64-encoded ciphertext.

Decrypts the message and displays the decrypted message.

Disclaimer
This example is for educational purposes and may not provide the same level of security as established libraries. In a production environment, it is recommended to use well-established cryptographic libraries for encryption and decryption.

css

Feel free to customize the README.md to suit your needs and provide additional information if required.

Imports:

    ```go
    import (
    "bufio"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "io"
    "os"
    "strings"
    )

bufio: Provides buffered I/O for reading the user's input.

crypto/aes: Implements the AES block cipher.

crypto/cipher: Defines the interface for cryptographic ciphers.

crypto/rand: Provides a source of random data.

encoding/base64: Used for encoding and decoding base64 data.

fmt: Implements formatted I/O.

io: Provides basic I/O interfaces.

os: Offers a way to interact with the operating system.

strings: Provides string manipulation functions.

Main Function:
```go
func main() {
key := "supersecretkey" // replace this with a secure key in a real-world scenario

Defines the key used for encryption and decryption.

    fmt.Print("Enter a message to encrypt: ")
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    plaintext := scanner.Text()

Prompts the user to enter a message, reads it from the console, and stores it in the plaintext variable.

    salt := generateSalt()

Calls the generateSalt function to create a random salt.

    paddedKey := padKey([]byte(key))

Calls the padKey function to ensure the key is exactly 32 bytes.

    encryptedMessage, err := encrypt([]byte(plaintext), paddedKey, salt)
    if err != nil {
    fmt.Println("Encryption error:", err)
    return
    }

Calls the encrypt function to encrypt the user's message and handles any encryption errors.

    fmt.Println("Encrypted message:", base64.StdEncoding.EncodeToString(encryptedMessage))

Prints the encrypted message in base64 encoding.

    decryptedMessage, err := decrypt(encryptedMessage, paddedKey, salt)
    if err != nil {
    fmt.Println("Decryption error:", err)
    return
    }

Calls the decrypt function to decrypt the message and handles any decryption errors.

`    fmt.Println("Decrypted message:", string(decryptedMessage))`
Prints the decrypted message.

Helper Functions:

generateSalt:

    func generateSalt() []byte {
    salt := make([]byte, 16)
    if \_, err := io.ReadFull(rand.Reader, salt); err != nil {
    panic(err)
    }
    return salt
    }

Generates a random 16-byte salt using crypto/rand.
padKey:

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

Pads or truncates the key to ensure it is exactly 32 bytes.

encrypt:

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

Encrypts the plaintext using AES in CFB mode.
decrypt:

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

Decrypts the ciphertext using AES in CFB mode.
This program demonstrates a simple encryption and decryption process using the AES cipher with manual key management. Keep in mind that manual cryptography implementation can be error-prone and is not recommended for production use. For real-world scenarios, it's advised to use well-established cryptographic libraries.
