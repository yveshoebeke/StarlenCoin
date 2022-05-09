package data

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"starlencoin.com/packages/blockchain"
	"starlencoin.com/packages/config"
	"starlencoin.com/packages/wallets"
)

var (
	c  config.Config
	w  wallets.Wallet
	bc blockchain.Blockchain
)

// *************************************************************************************
// Data --
//	Methods:
//		MakeJSONString: Returns the block data struct in JSON format.
type Data struct {
	Type           string    `json:"type"`
	From           string    `json:"from"`
	To             string    `json:"to"`
	Amount         float64   `json:"amount"`
	Comment        string    `json:"comment"`
	Timestamp      time.Time `json:"timestamp"`
	Signature      []byte    `json:"signature"`
	Processed      bool      `json:"processed"`
	TransactionFee float64   `json:"transactionfee"`
	Status         string    `json:"status"`
	Hash           [32]byte  `json:"hash"`
}

// CalculateHash -- Calculate Data SHA256 hash.
func (d *Data) CalculateHash() [32]byte {
	// Save hash, status and processed flag
	savedHash := d.Hash
	savedProcessed := d.Processed
	savedStatus := d.Status
	// Set hash, status and processed flag to state when hash was calculated.
	d.Processed = false
	d.Status = "pending"
	d.Hash = [32]byte{}
	jsonData := d.MakeJSONString()
	// Restore hash, status and processed flag to original state.
	d.Hash = savedHash
	d.Processed = savedProcessed
	d.Status = savedStatus
	// Return the SHA256 hash of the json data string.
	return sha256.Sum256([]byte(jsonData))
}

// MakeJSONString -- Convert Block Data to JSON.
func (d *Data) MakeJSONString() string {
	jsonData, err := json.Marshal(d)
	if err != nil {
		fmt.Printf("MakeJSONString error: %s", err)
		return ""
	}

	return string(jsonData)
}

// WritePendingData --
//	Note: filename is the hash of the user controlled data (same that is signed), since record Hash changes after mining operation.
func (d *Data) WritePendingData() error {
	if d.Hash != [32]byte{} {
		if err := os.RemoveAll(filepath.Join(c.Datapaths.Pending, fmt.Sprintf("%x", d.Hash))); err != nil {
			return err
		}
	}
	d.CalculateHash()

	if err := ioutil.WriteFile(filepath.Join(c.Datapaths.Pending, fmt.Sprintf("%x", d.Hash)), []byte(d.MakeJSONString()), 0644); err != nil {
		return err
	}

	return nil
}

// AddToPendingTransactions -- Takes console input to create a new Block and add it to the Blockchain.
func (d *Data) AddToPendingTransactionData(from, to, amount, comment, trxtype string) error {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	// Fill struct with user input.
	d.Type = trxtype
	d.From = from
	d.To = to
	d.Amount, _ = strconv.ParseFloat(amount, 64)
	// if d.Type == "TRX" {
	// 	d.Amount *= -1
	// }
	d.Comment = comment
	// Trx created timestamp.
	d.Timestamp = time.Now()
	// Calculate this transaction fee from the transaction amount.
	d.TransactionFee = math.Abs(d.Amount) * c.Rewards.TransactionFee
	// Set status
	d.Processed = false
	d.Status = "pending"
	// Sign it.
	d.Signature = d.SignTransactionData(w.Name)
	d.Hash = d.CalculateHash()
	// Append it to blokchain pending data.
	bc.PendingData = append(bc.PendingData, *d)
	if err := d.WritePendingData(); err != nil {
		return err
	}

	return nil
}

// SignTransactionData --
func (d *Data) SignTransactionData(u string) []byte {
	// Sign it with user's private key.
	dirname := fmt.Sprintf("%x", w.Account)
	// Get the user controlled fields and hash it.
	signedDataHash := sha256.Sum256([]byte(fmt.Sprintf("%s%s%s%0.2f%s%s", d.Type, d.From, d.To, d.Amount, d.Comment, d.Timestamp.Format(time.RFC3339))))
	// Read the private key.
	rawPrivateKey, _ := ioutil.ReadFile(filepath.Join(c.Datapaths.Wallets, dirname, "private.pem"))
	// Parse it - RSA PKCS1=v1_5.
	privateKeyBlock, _ := pem.Decode([]byte(rawPrivateKey))
	privateKeyParseResult, _ := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	// Sign the digest.
	signed, _ := rsa.SignPKCS1v15(rand.Reader, privateKeyParseResult, crypto.SHA256, signedDataHash[:])

	return signed
}

// VerifySignature -- Verify the signature of the User contained in the "From/To" field (originator).
func (d *Data) VerifySignature() error {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	var keyfilename string
	// Create the digest and hash it.
	signedData := d.Type + d.From + d.To + fmt.Sprintf("%0.2f", d.Amount) + d.Comment + d.Timestamp.Format(time.RFC3339)
	signedDataHash := sha256.Sum256([]byte(signedData))
	// Read the public key belonging to: ...
	// If Transaction type = DEP(osit), owner is in To field, others owner is in From field.
	switch d.Type {
	case "DEP":
		keyfilename = fmt.Sprintf("%x", sha256.Sum256([]byte(d.To)))
	default:
		keyfilename = fmt.Sprintf("%x", sha256.Sum256([]byte(d.From)))
	}

	// Get the Public key from the owner/creator of the transaction.
	rawPublicKey, err := ioutil.ReadFile(filepath.Join(c.Datapaths.PublicKeys, keyfilename))
	if err != nil {
		return err
	}
	// Parse it - RSA PKCS1=v1_5.
	publicKeyBlock, _ := pem.Decode([]byte(rawPublicKey))
	parseResult, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return err
	}
	// Verify it and return result (ok: err => nil).
	err = rsa.VerifyPKCS1v15(parseResult, crypto.SHA256, signedDataHash[:], d.Signature)
	if err != nil {
		return err
	}

	return nil
}
