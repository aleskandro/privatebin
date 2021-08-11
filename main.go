package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/pborman/getopt/v2"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/pbkdf2"

	"github.com/aleskandro/privatebin/utils"
)

const (
	specIterations       = 100000
	specKeySize          = 256
	specTagSize          = 128
	specAlgorithm        = "aes"
	specMode             = "gcm"
	specCompression      = "none"
	defaultPrivateBinURL = "https://privatebin.net"
)

var privateBinBaseURL string

// PasteRequest .
type PasteRequest struct {
	V     int              `json:"v"`
	AData []interface{}    `json:"adata"`
	Meta  PasteRequestMeta `json:"meta"`
	CT    string           `json:"ct"`
}

// PasteRequestMeta .
type PasteRequestMeta struct {
	Expire string `json:"expire"`
}

// PasteResponse .
type PasteResponse struct {
	Status      int    `json:"status"`
	ID          string `json:"id"`
	URL         string `json:"url"`
	DeleteToken string `json:"deletetoken"`
}

// PasteContent .
type PasteContent struct {
	Paste string `json:"paste"`
}

// PasteSpec .
type PasteSpec struct {
	IV          string
	Salt        string
	Iterations  int
	KeySize     int
	TagSize     int
	Algorithm   string
	Mode        string
	Compression string
}

// SpecArray .
func (spec *PasteSpec) SpecArray() []interface{} {
	return []interface{}{
		spec.IV,
		spec.Salt,
		spec.Iterations,
		spec.KeySize,
		spec.TagSize,
		spec.Algorithm,
		spec.Mode,
		spec.Compression,
	}
}

// PasteData .
type PasteData struct {
	*PasteSpec
	Data []byte
}

// adata .
func (paste *PasteData) adata() []interface{} {
	return []interface{}{
		paste.SpecArray(),
		"plaintext",
		0,
		0,
	}
}

func init() {
	helpMsg := fmt.Sprintf("The PrivateBin server to send text to (default to \"%s\").",
		defaultPrivateBinURL)
	getopt.FlagLong(&privateBinBaseURL, "server", 's', helpMsg)
}

func main() {
	// Read from STDIN (Piped input)
	getopt.ParseV2()
	if len(privateBinBaseURL) == 0 {
		privateBinBaseURL = defaultPrivateBinURL
	}

	// Validation of the URI
	_, err := url.ParseRequestURI(privateBinBaseURL)
	if err != nil {
		panic(err)
	}

	// Removes leading slash(s)
	for privateBinBaseURL[len(privateBinBaseURL)-1] == '/' {
		privateBinBaseURL = privateBinBaseURL[:len(privateBinBaseURL)-1]
	}

	fmt.Println(privateBinBaseURL)
	input, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
		return
	}

	// Remove extra line breaks to prevent PrivateBin from breaking.
	if bytes.HasSuffix(input, []byte("\n")) {
		input = input[:len(input)-1]
	}

	// Marshal the paste content to escape JSON characters.
	pasteContent, err := json.Marshal(&PasteContent{Paste: utils.StripANSI(string(input))})
	if err != nil {
		panic(err)
		return
	}

	// Generate a master key for the paste.
	masterKey, err := utils.GenRandomBytes(32)
	if err != nil {
		panic(err)
		return
	}

	// Encrypt the paste data
	pasteData, err := encrypt(masterKey, pasteContent)
	if err != nil {
		panic(err)
		return
	}

	// Create a new Paste Request.
	pasteRequest := &PasteRequest{
		V:     2,
		AData: pasteData.adata(),
		Meta: PasteRequestMeta{
			Expire: "1week",
		},
		CT: utils.Base64(pasteData.Data),
	}

	// Get the Request Body.
	body, err := json.Marshal(pasteRequest)
	if err != nil {
		panic(err)
		return
	}

	// Create a new HTTP Client and HTTP Request.
	client := &http.Client{}
	req, err := http.NewRequest("POST", privateBinBaseURL, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
		return
	}

	// Set the request headers.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("X-Requested-With", "JSONHttpRequest")

	// Run the http request.
	res, err := client.Do(req)
	if err != nil {
		panic(err)
		return
	}

	// Close the request body once we are done.
	defer func() {
		if err := res.Body.Close(); err != nil {
			panic(err)
			return
		}
	}()

	// Read the response body.
	response, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
		return
	}

	// Decode the response.
	pasteResponse := &PasteResponse{}
	if err := json.Unmarshal(response, &pasteResponse); err != nil {
		panic(err)
		return
	}

	fmt.Printf("%s%s#%s\n", privateBinBaseURL, pasteResponse.URL, base58.Encode(masterKey))
}

func encrypt(master []byte, message []byte) (*PasteData, error) {
	// Generate a initialization vector.
	iv, err := utils.GenRandomBytes(12)
	if err != nil {
		return nil, err
	}

	// Generate salt.
	salt, err := utils.GenRandomBytes(8)
	if err != nil {
		return nil, err
	}

	// Create the Paste Data and generate a key.
	paste := &PasteData{
		PasteSpec: &PasteSpec{
			IV:          utils.Base64(iv),
			Salt:        utils.Base64(salt),
			Iterations:  specIterations,
			KeySize:     specKeySize,
			TagSize:     specTagSize,
			Algorithm:   specAlgorithm,
			Mode:        specMode,
			Compression: specCompression,
		},
	}
	key := pbkdf2.Key(master, salt, paste.Iterations, 32, sha256.New)

	// Get the "adata" for the paste.
	adata, err := json.Marshal(paste.adata())
	if err != nil {
		return nil, err
	}

	// Create a new Cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new GCM.
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// Sign the message.
	data := gcm.Seal(nil, iv, message, adata)

	// Update and return the paste data.
	paste.Data = data

	return paste, nil
}
