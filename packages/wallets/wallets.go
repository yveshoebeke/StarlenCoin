package wallets

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"starlencoin.com/packages/config"
	"starlencoin.com/packages/utils"
)

var Cfg config.Config

// *************************************************************************************
// Wallets --
type Wallets struct {
	Wallets []Wallet `json:"wallets"`
}

// LoadWallets - Read wallet data from disk and insert in wallets structure.
func (ws *Wallets) LoadWallets() error {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	// Make sure wallets structure slice is empty.
	ws.Wallets = ws.Wallets[:0]
	// Read all wallet files from data directory.
	walletFiles, err := ioutil.ReadDir(c.Datapaths.Wallets)
	if err != nil {
		return err
	}
	// Read each file and push it in the Wallets structure.
	fmt.Printf("\nProcessing from %s:\n\n", c.Datapaths.Wallets)
	for _, f := range walletFiles {
		if f.IsDir() {
			var wallet Wallet
			jsonWallet, err := ioutil.ReadFile(filepath.Join(c.Datapaths.Wallets, f.Name(), "wallet.json"))
			if err != nil {
				return err
			}
			if err := json.Unmarshal([]byte(jsonWallet), &wallet); err != nil {
				return err
			}
			ws.Wallets = append(ws.Wallets, wallet)
		}
	}

	return nil
}

// *************************************************************************************
type Wallet struct {
	Account   [32]byte  `;son:"account"`
	Name      string    `json:"name"`
	RealName  string    `json:"realname"`
	Role      string    `json:"role"`
	Email     string    `json:"email"`
	Phone     string    `json:"phone"`
	Bank      Bank      `json:"bank"`
	Password  string    `json:"password"`
	LastLogin time.Time `json:"lastlogin"`
	Created   time.Time `json:"created"`
}

type Bank struct {
	Name    string `json:"name"`
	Routing string `json:"routing"`
	Account string `json:"account"`
}

func (w *Wallet) MakeJSONString() (string, error) {
	jsonData, err := json.Marshal(w)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// Register --
// Check if already exists.
// Create {wallet data path}/{name} diretory.
// Create wallet.json file.
// Create private and public keys.
func (w *Wallet) Register(name, realname, role, email, phone, bankname, bankrouting, bankaccount, password string) error {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	// Record wallet data
	w.Name = name
	w.Account = sha256.Sum256([]byte(w.Name))
	w.RealName = realname
	w.Role = role
	w.Email = email
	w.Phone = phone
	w.Bank.Name = bankname
	w.Bank.Routing = bankrouting
	w.Bank.Account = bankaccount
	w.Created = time.Now()
	// Encode the password string.
	pwd, err := utils.HashAndSalt([]byte(password))
	if err != nil {
		return err
	}
	w.Password = pwd
	w.LastLogin = time.Now()
	dirname := fmt.Sprintf("%x", w.Account)
	// Check if directory exists.
	if _, err := os.Stat(filepath.Join(c.Datapaths.Wallets, dirname)); !os.IsNotExist(err) {
		return fmt.Errorf("wallet already exists for %s", w.Name)
	}
	// CreateDirectory.
	if err := os.Mkdir(filepath.Join(c.Datapaths.Wallets, dirname), 0755); err != nil {
		return err
	}
	fmt.Println("Account:", dirname, "created.")
	// Write wallet.json file.
	jsonWallet, err := w.MakeJSONString()
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(c.Datapaths.Wallets, dirname, "wallet.json"), []byte(jsonWallet), 0644); err != nil {
		return err
	}

	// Create private and public keys.
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("error generating key: %s\n", err)
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey
	// Write private key.
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create(filepath.Join(c.Datapaths.Wallets, dirname, "private.pem"))
	if err != nil {
		fmt.Printf("error creating private.pem: %s\n", err)
		os.Exit(1)
	}
	if err := pem.Encode(privatePem, privateKeyBlock); err != nil {
		fmt.Printf("error encoding private pem: %s\n", err)
	}
	// Write public key.
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publickey)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create(filepath.Join(c.Datapaths.PublicKeys, dirname))
	if err != nil {
		fmt.Printf("error creating public.pem: %s\n", err)
		os.Exit(1)
	}
	if err := pem.Encode(publicPem, publicKeyBlock); err != nil {
		fmt.Printf("error encoding public pem: %s", err)
		os.Exit(1)
	}

	return nil
}

// VerifyLogin --
func (w *Wallet) VerifyLogin(name, pwd string) (string, error) {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("@L254:", Cfg.Datapaths.Wallets)
	// Check if User exists.
	dirname := fmt.Sprintf("%x", sha256.Sum256([]byte(name)))
	if _, err := os.Stat(filepath.Join(c.Datapaths.Wallets, dirname)); os.IsNotExist(err) {
		return "", err
	}
	// Get Hashed Password
	jsonWallet, err := ioutil.ReadFile(filepath.Join(filepath.Join(c.Datapaths.Wallets, dirname, "wallet.json")))
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal([]byte(jsonWallet), &w); err != nil {
		return "", err
	}
	if err := utils.ComparePasswords(string(w.Password), []byte(pwd)); err != nil {
		return "", err
	}
	// Save last login before update.
	lastlogin := w.LastLogin.Format(time.RFC3339)

	w.LastLogin = time.Now()
	// Update wallet.json
	stringWallet, err := w.MakeJSONString()
	if err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(filepath.Join(c.Datapaths.Wallets, dirname, "wallet.json"), []byte(stringWallet), 0644); err != nil {
		return "", err
	}

	return lastlogin, nil
}
