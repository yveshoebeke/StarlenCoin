package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"starlencoin.com/packages/config"
	"starlencoin.com/packages/utils"
)

const (
	BLOCKCHAINNAME = "Starlen"     // Name of this blockchain.
	CRYPTONAME     = "StarlenCoin" // Name of the crypto currency.
)

var (
	// CONFIGPATH = os.Getenv("BC_CONFIG_PATH") // Local example -> /Users/yves/Projects/StarlenCoin/data/config/config.json
	// consoleReader             = bufio.NewReader(os.Stdin)   // Console reader
	targetHash                = [32]byte{}
	Cfg                       config.Config
	c                         config.Config
	ws                        Wallets
	w                         Wallet
	d                         Data
	b                         Block
	n                         Node
	bc                        Blockchain
	from, to, amount, comment string
	selection, sig            string
	user                      string
)

// *************************************************************************************
// Config -- App configuration structure and methods (file format: TOML)
// type Config struct {
// 	Title     string      `toml:"title"`
// 	Owner     OwnerInfo   `toml:"owner"`
// 	Datapaths DatapathCfg `toml:"datapaths"`
// 	Mining    MiningCfg   `toml:"mining"`
// 	Rewards   RewardsCfg  `toml:"rewards"`
// }

// type OwnerInfo struct {
// 	Name    string `toml:"name"`
// 	Url     string `toml:"url"`
// 	Contact string `toml:"contact"`
// }

// type DatapathCfg struct {
// 	Blocks     string `toml:"blocks"`
// 	Pending    string `toml:"pending"`
// 	Wallets    string `toml:"wallets"`
// 	PublicKeys string `toml:"publickeys"`
// }

// type MiningCfg struct {
// 	Blocksize  uint `toml:"blocksize"`
// 	Difficulty uint `toml:"difficulty"`
// }

// type RewardsCfg struct {
// 	MinerReward    float64 `toml:"minerreward"`
// 	TransactionFee float64 `toml:"transactionfee"`
// }

// func (c *Config) ReadConfig() error {
// 	buf, err := ioutil.ReadFile(config.CONFIGPATH)
// 	if err != nil {
// 		return err
// 	}
// 	cfg := string(buf)
// 	if _, err := toml.Decode(cfg, c); err != nil {
// 		return err
// 	}

// 	return nil
// }

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

// *************************************************************************************
// Node --
type Node struct {
	Name      string    `json:"name"`
	Url       string    `json:"url"`
	Timestamp time.Time `json:"timestamp"`
	Active    bool      `json:"participant"`
}

// Register -- Add node to pool.
func (n *Node) Register(name, url string) {
	n.Name = name
	n.Url = url
	n.Timestamp = time.Now()
	n.Active = true

	bc.Nodes = append(bc.Nodes, *n)
}

// Deregister -- Set specified node to inactive.
func (n *Node) Deregister(name string) error {
	var nodeFound bool = false
	for _, n := range bc.Nodes {
		if n.Name == name {
			nodeFound = true
			n.Active = false
			break
		}
	}

	if nodeFound {
		return nil
	} else {
		return errors.New("Node not found")
	}
}

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

// *************************************************************************************
// Block --
//	Methods:
//		CalculateHash: Returns SHA256 hash of the block in JSON format.
//		MakeJSONString: Marshals Block structure into a JSON string.
//		WriteBlock: Writes the block to disk in JSON format with its hash as filename.
type Block struct {
	Index             uint      `json:"index"`
	Timestamp         time.Time `json:"timestamp"`
	Nonce             uint      `json:"nonce"`
	Difficulty        uint      `json:"difficulty"`
	Confirmations     uint      `json:"confirmations"`
	PreviousHash      [32]byte  `json:"previoushash"`
	BlockValue        float64   `json:"blockvalue"`
	Miner             string    `json:"miner"`
	MinerReward       float64   `json:"minerreward"`
	TransactionsFee   float64   `json:"transactionsFee"`
	TransactionsCount uint      `json:"transactionscount"`
	MerkleRoot        [32]byte  `json:"merkleroot"`
	Data              []Data    `json:"data"`
	Hash              [32]byte  `json:"hash"`
}

// CalculateHash -- Calculate Block SHA256 hash.
//	Remove hash -> get json -> restore hash -> hash json
func (b *Block) CalculateHash() [32]byte {
	savedHash := b.Hash
	b.Hash = [32]byte{}
	jsonBlock := b.MakeJSONString()
	b.Hash = savedHash
	return sha256.Sum256([]byte(jsonBlock))
}

// MakeJSONString -- Convert Block struct to JSON.
func (b *Block) MakeJSONString() string {
	jsonBlock, err := json.Marshal(b)
	if err != nil {
		fmt.Printf("MakeJSONString error: %s", err)
		return ""
	}
	return string(jsonBlock)
}

// WriteBlock - Write block to disk
func (b *Block) WriteBlock() error {
	if err := ioutil.WriteFile(filepath.Join(c.Datapaths.Blocks, fmt.Sprintf("%x", b.Hash)), []byte(b.MakeJSONString()), 0644); err != nil {
		return err
	}

	return nil
}

// Certify --
func (b *Block) Certify() error {
	// Check hash
	fmt.Printf("Processing block - Index: %d Hash: %x\n", b.Index, b.Hash)
	fmt.Printf("\tBlock hash: %x - Calculated: %x [%t]\n", b.Hash, b.CalculateHash(), b.Hash == b.CalculateHash())
	fmt.Printf("\tReported: %d vs Stored: %d [%t]\n", int(b.TransactionsCount), len(b.Data), int(b.TransactionsCount) == len(b.Data))
	// Check trx, for each:
	// 	-hash
	//	-signature
	var dataHashes [][32]byte
	for i, d := range b.Data {
		dataHashes = append(dataHashes, d.Hash)
		sig = "ok"
		if err := d.VerifySignature(); err != nil {
			sig = "false"
		}
		fmt.Printf("\t%d. Data Hash: %x - Calculated: %x [%t] - Signature: %s\n", i+1, d.Hash, d.CalculateHash(), d.Hash == d.CalculateHash(), sig)
	}
	// Check Merkle tree
	merkleroot, _ := utils.DeriveMerkleRootHash(dataHashes)
	fmt.Printf("\tMerkle root: %t\n", b.MerkleRoot == merkleroot)

	return nil
}

// *************************************************************************************
// Blockchain --
//	Methods:
//		CreateGenesisBlock: Creates genesis block and pushes it up to chain.
//		GetLatestBlock: Simplistic func to get the last block in the chain slice (good for initial population).
//		AddNewBlockByHash: Adds new block to the chain by properly evaluating the previous hashes.
//		ReadAndAppendBlock: Reads block from data directory and appends it to the chain.
//		ReloadIteration: Uses above methods to reload chain from disk.
//		AddBlocksToChain: Adds a number of blocks to the chain using the simplistic funcs (good for initial population).
//		GetLastBlock: Returns the block that is not referenced by any of the previous blocks.
//		FollowTheLinks: Iterate through the blockchain using links and computed block hash.
//		AddNewBlockFromConsole: Captures user data, generate a Block and link it in the Blockchain.
//		DisplayStarlenCoin: Iterates over Blockchain array and gives short display.
//		HashVerification: Iterates over blockchain, calculates hash and compares it to stored hash, reports discrepancies.
type Blockchain struct {
	Chain       []Block `json:"chain"`
	PendingData []Data  `json:"pendingdata"`
	Nodes       []Node  `json:"nodes"`
	Name        string  `json:"name"`
	Cryptoname  string  `json:"cryptoname"`
}

// createGenesisBlock -- Initializes everything.
func (bc *Blockchain) createStarlenCoin() error {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	// Remove all saved blocks from data directory.
	d, err := os.Open(c.Datapaths.Blocks)
	if err != nil {
		return err
	}
	defer d.Close()

	blockFiles, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	// Read each file and remove it.
	for _, f := range blockFiles {
		if err := os.RemoveAll(filepath.Join(c.Datapaths.Blocks, f)); err != nil {
			return err
		}
	}
	// Remove all saved pending data transactions from data directory.
	d, err = os.Open(c.Datapaths.Pending)
	if err != nil {
		return err
	}
	defer d.Close()

	blockFiles, err = d.Readdirnames(-1)
	if err != nil {
		return err
	}
	// Read each file and remove it.
	for _, f := range blockFiles {
		if err := os.RemoveAll(filepath.Join(c.Datapaths.Pending, f)); err != nil {
			return err
		}
	}
	// Set some blockchain characteristics.
	bc.Name = BLOCKCHAINNAME   // Blockchain name.
	bc.Cryptoname = CRYPTONAME // Currency name.
	// Init Blockchain and create Genesis block on chain.
	bc.CreateGenesisBlock()
	fmt.Printf("StarlenCoin Blockchain generated with Genesis Block.\n")

	return nil
}

// CreateGenesisBlock -- Create Genesis block and push it up the chain (1st element).
func (bc *Blockchain) CreateGenesisBlock() {
	d := Data{
		Type:           "SLC",
		From:           "SLC",
		To:             "SLC",
		Amount:         0.0,
		Comment:        "Genesis to a solution looking for a problem.",
		Timestamp:      time.Now(),
		Signature:      []byte{},
		Hash:           [32]byte{},
		Processed:      true,
		TransactionFee: 0,
		Status:         "Completed",
	}
	d.Signature = d.SignTransactionData(d.From)
	d.Hash = d.CalculateHash()
	merkleroot, _ := utils.DeriveMerkleRootHash([][32]byte{d.Hash})
	b := Block{
		Index:             0,
		Timestamp:         time.Now(),
		PreviousHash:      [32]byte{},
		Nonce:             0,
		Difficulty:        0,
		Confirmations:     0,
		BlockValue:        0,
		Miner:             w.Name,
		MinerReward:       0,
		TransactionsFee:   0,
		TransactionsCount: 1,
		MerkleRoot:        merkleroot,
		Data:              []Data{d},
		Hash:              [32]byte{},
	}
	b.Hash = b.CalculateHash()
	bc.Chain = []Block{}
	bc.Chain = append(bc.Chain, b)
	_ = b.WriteBlock()
}

// GetLatesBlock - Retrieve latest (most recent) block in the chain.
func (bc *Blockchain) GetLatestBlock() Block {
	return bc.Chain[len(bc.Chain)-1]
}

// GetLastBlock - Find the last block in the blockchain, ie. the block that is not referenced by any of the previous blocks.
func (bc *Blockchain) GetLastBlock() (Block, error) {
	var lastBlock Block
	var prevHashNotFound bool
	// Check if Blockchain is empty
	if len(bc.Chain) == 0 {
		return Block{}, errors.New("Blockchain is empty")
	}
	// Check if only 1 block present (should be the Genisis block).
	if len(bc.Chain) == 1 {
		return bc.Chain[0], nil
	}
	// Iterate over Blockchain until we find a previous hash that doesn't eists.
	for _, block := range bc.Chain {
		prevHashNotFound = true
		for _, targetBlock := range bc.Chain {
			if block.Hash == targetBlock.PreviousHash {
				prevHashNotFound = false
			}
		}
		if prevHashNotFound {
			lastBlock = block
			break
		}
	}
	// Return according to search results.
	if !prevHashNotFound {
		return Block{}, errors.New("Blockchain linkage error, no Block qualified as last Block")
	} else {
		return lastBlock, nil
	}
}

// ReadPreviousBlock - Follow the link to find the block whose calculated hash matches.
func (bc *Blockchain) ReadPreviousBlock(previousBlockHash [32]byte) (Block, error) {
	b := Block{}
	var savedHash [32]byte
	blockFound := false
	for _, b = range bc.Chain {
		savedHash = b.Hash
		b.Hash = [32]byte{}
		if b.CalculateHash() == previousBlockHash && b.CalculateHash() == savedHash {
			b.Hash = savedHash
			blockFound = true
			break
		}
	}

	if blockFound {
		return b, nil
	} else {
		return Block{}, errors.New("Chain Broken at " + fmt.Sprintf("%x", savedHash))
	}
}

// DisplayBlock -- Output Block and associated Data.
func (b *Block) DisplayBlock(BlockCollection map[string]Block, CollectionKeys []string) error {
	for _, k := range CollectionKeys {
		*b = BlockCollection[k]
		fmt.Printf("\nIndex: %d Time: %s Nonce: %d Difficulty: %d Block value: %0.2f\n", b.Index, b.Timestamp.Format(time.RFC3339), b.Nonce, b.Difficulty, b.BlockValue)
		fmt.Printf("\tMiner: %s MinerReward: %0.5f Transactions fee: %0.5f Number of transactions: %d\n", b.Miner, b.MinerReward, b.TransactionsFee, b.TransactionsCount)
		fmt.Printf("\t   PrevHash: %x\n", b.PreviousHash)
		fmt.Printf("\t       Hash: %x\n", b.Hash)
		fmt.Printf("\tMerkle Root: %x\n", b.MerkleRoot)
		fmt.Printf("\tTransaction Data:\n")
		for i, d := range b.Data {
			fmt.Printf("\t%d. Type: %s From: %s To: %s Amount: %0.2f TransactionFee: %0.5f Comment: %s Time: %s\n", i+1, d.Type, d.From, d.To, d.Amount, d.TransactionFee, d.Comment, d.Timestamp.Format(time.RFC3339))
			var verified string = "OK"
			if err := d.VerifySignature(); err != nil {
				verified = "ERR"
			}
			fmt.Printf("\t\tSignature: [%x ... %x][%s]\n", d.Signature[0:2], d.Signature[len(d.Signature)-2:len(d.Signature)], verified)
			fmt.Printf("\t\tProcessed: %t Status: %s\n", d.Processed, d.Status)
			fmt.Printf("\t\tHash: %x\n", d.Hash)
		}
	}

	return nil
}

// FollowTheLinks -- POC of iterating from last -> Genesis block by following the links.
func (bc *Blockchain) FollowTheLinks(f string) error {
	var count int = 0
	BlockCollection := make(map[string]Block)
	// Locate last block, this will be our starting point and follow the previous hash down the chain.
	b, err := bc.GetLastBlock()
	if err != nil {
		return err
	}
	// Info only - last block hash.
	fmt.Printf("[Last block = %x]\n\n", b.Hash)
	// Loop - follow previous haash until genisis encounterd.
	for {
		count++
		// Push Blocks onto the map.
		BlockCollection[b.Timestamp.Format(time.RFC3339)] = b
		// Check if this is genisis block, if so we're done.
		if b.PreviousHash == [32]byte{} {
			break
		}
		// Get the previous block.
		b, err = bc.ReadPreviousBlock(b.PreviousHash)
		if err != nil {
			return err
		}
	}
	// Display number of blocks found.
	fmt.Printf("\nTotal of %d Blocks in the Blockchain.\n", count)

	// Execute callback function
	switch f {
	case "display":
		keys := make([]string, 0, len(BlockCollection))
		for k := range BlockCollection {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if err := b.DisplayBlock(BlockCollection, keys); err != nil {
			return err
		}
	default:
		return errors.New("wrong callback option")
	}
	return nil
}

// ReloadIteration - Iterate (follow the links) over the blockchain ... correct this
func (bc *Blockchain) ReloadIteration() error {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	// Set some blockchain characteristics.
	bc.Name = BLOCKCHAINNAME   // Blockchain name.
	bc.Cryptoname = CRYPTONAME // Currency name.
	// Make sure blockchain chain slice is empty.
	bc.Chain = bc.Chain[:0]
	// Read all block files from data directory and push them on the chain.
	blockFiles, err := ioutil.ReadDir(c.Datapaths.Blocks)
	if err != nil {
		return err
	}
	// Read each file and push it on the chain.
	fmt.Printf("\nProcessing from %s:\n\n", c.Datapaths.Blocks)
	for i, f := range blockFiles {
		fmt.Printf("%d. %s\n", i+1, f.Name())
		bc.ReadAndAppendBlock(f.Name())
	}

	// Make sure blockchain pending data slice is empty.
	bc.PendingData = bc.PendingData[:0]
	// Read all pending files from pending directory and push them on the chain.
	pendingFiles, err := ioutil.ReadDir(c.Datapaths.Pending)
	if err != nil {
		fmt.Printf("Error reading blockchain pending data directory: %s\n", err)
	}
	// Read each file and push it on the chain.
	fmt.Printf("\nProcessing from %s:\n\n", c.Datapaths.Pending)
	for i, f := range pendingFiles {
		fmt.Printf("%d. %s\n", i+1, f.Name())
		bc.ReadAndAppendPending(f.Name())
	}

	return nil
}

// ReadAndAppendBlock -- Read the given block, from JSON into the struct and append the chain.
func (bc *Blockchain) ReadAndAppendBlock(hashName string) {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	// Make a block object to work with
	var block Block
	// Rerad block from disk (it's stored in json format).
	jsonBlock, err := ioutil.ReadFile(filepath.Join(c.Datapaths.Blocks, hashName))
	if err != nil {
		fmt.Printf("Read Block File error: %s\n", err)
	}
	// Move json into struct
	if err := json.Unmarshal([]byte(jsonBlock), &block); err != nil {
		fmt.Printf("Unmarshall error: %s\n", err)
	}
	// Add it to the blockchain
	bc.Chain = append(bc.Chain, block)
}

// ReadAndAppendPending - Read the given block, from JSON into the struct and append the chain.
func (bc *Blockchain) ReadAndAppendPending(hashName string) {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	// Make a block object to work with
	var data Data
	// Rerad block from disk (it's stored in json format).
	jsonBlock, err := ioutil.ReadFile(filepath.Join(c.Datapaths.Pending, hashName))
	if err != nil {
		fmt.Printf("Read Pending Block File error: %s\n", err)
	}
	// Move json into struct
	if err := json.Unmarshal([]byte(jsonBlock), &data); err != nil {
		fmt.Printf("Unmarshall error: %s\n", err)
	}
	// Add it to the blockchain
	bc.PendingData = append(bc.PendingData, data)
}

// Iterate over the Blockchain array and display.
func (bc *Blockchain) DisplayStarlenCoin() {
	// Dislay blocks on chain data.
	for _, b := range bc.Chain {
		fmt.Printf("Index: %d\nTime: %s\nPrev Block Hash: %x\nThis Block Hash: %x\nNonce: %d\n", b.Index, b.Timestamp.Format(time.RFC3339), b.PreviousHash, b.Hash, b.Nonce)
		fmt.Printf("Transaction Data:\n")
		for _, d := range b.Data {
			fmt.Printf("%s\n", d.MakeJSONString())
		}
	}
}

// Iterates over Blockchain arrayand recalculates hash and compares it to stored hash.
func (bc *Blockchain) HashVerification() map[[32]byte]Block {
	// Make error map -> [GeneratedHash]Block
	HashErrors := make(map[[32]byte]Block)
	// Iterate through the chain, recalculate hash and compare with stored hash.
	for _, b := range bc.Chain {
		generatedHash := b.CalculateHash()
		if !bytes.Equal(generatedHash[:], b.Hash[:]) {
			HashErrors[generatedHash] = b
		}
	}
	return HashErrors
}

// Get pending transactions and create a block with hash code compilation according to difficulty level.
// func (bc *Blockchain) MinePendingDataTransactions() error {
func (bc *Blockchain) MinePendingDataTransactions() error {
	c, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	var pendingTrxCount int = 0
	// Check if there is anything at all Pending.
	if len(bc.PendingData) == 0 {
		return errors.New("no pending data transactions available")
	}
	// Check how many Pending Data Transactions have not been processed previously.
	for i, d := range bc.PendingData {
		if !d.Processed {
			if err := d.VerifySignature(); err != nil {
				continue
			}
			fmt.Printf("%d\t%x\t%s\n", i+1, d.Hash, d.Timestamp.Format(time.RFC3339))
			pendingTrxCount++
		}
	}
	// If there were Pending transactions, but all were previously processed (processed == true), return with notification in error.
	if pendingTrxCount == 0 {
		return errors.New("all transactions were previously processed - no block added")
	}
	fmt.Printf("\n%d Data Transactions recorded.\n%d Data Transactions to process.\n\nProcessing:\n", len(bc.PendingData), pendingTrxCount)
	// Initialize needed data elements: new Data and init accumulaters and counters.
	var (
		processedTrxHashes [][32]byte // Keep tabs of trxs added to block, to update status after block is created.
		merkleHashes       [][32]byte // Slice of transaction data hashes.
		dataCount          int        = 0
	)
	b.Data = []Data{}       // Empty Data struct.
	b.Confirmations = 0     // Number of Confirmations (not implemented yet).
	b.TransactionsCount = 0 // Number of transactions.
	b.TransactionsFee = 0   // Total TransactionsFee.
	b.BlockValue = 0        // Total value of all transactions.
	// Iterate through Pending transactions and start process:
	// Note: The number of trx's to process could be limited by the value of c.Mining.Blocksize (c.Blockzize 0 eleminates check).
	for _, d := range bc.PendingData {
		if c.Mining.Blocksize > 0 && b.TransactionsCount == c.Mining.Blocksize {
			break
		}
		// If Signature is no good, set as processed, set appropriate status and skip;
		// ... else, set data transaction header info, re-calculate hash and push it up the Block Data slice.
		// ... and keep track of trx's processed to set status after block is forulated and saved.
		if err := d.VerifySignature(); err != nil {
			d.Processed = true
			d.Status = "Invalid Signature"
			fmt.Printf("%x [Rejected: %s]\n", d.Hash, d.Status)
			bc.PendingData[dataCount] = d
			if err := d.WritePendingData(); err != nil {
				return err
			}
		} else {
			// Skip previously processed pending trx's.
			if d.Processed {
				continue
			}
			// Set Status and Processed indicators.
			processedTrxHashes = append(processedTrxHashes, d.Hash)
			// Keep track of TransactionCount, TransactionFee and Amount totals sum for Block Header.
			b.TransactionsCount++
			b.TransactionsFee += d.TransactionFee
			b.BlockValue += math.Abs(d.Amount)
			b.Miner = string(w.Account[:])
			bc.PendingData[dataCount] = d
			// Re-establish hash, and append it to the Merkle tree leaves slice.
			merkleHashes = append(merkleHashes, d.Hash)
			// Inform Data Transaction being pushed on the Block Data slice.
			fmt.Printf("%x\n", d.Hash)
			b.Data = append(b.Data, d)
			if err := d.WritePendingData(); err != nil {
				return err
			}
			// Set status for appended data, but not yet in the pending records.
			b.Data[len(b.Data)-1].Processed = true
			b.Data[len(b.Data)-1].Status = "Completed"
		}
	}
	// Get last Block in Chain to get PreviousHash and Index value when adding the new block.
	lb, err := bc.GetLastBlock()
	if err != nil {
		return err
	}
	// Start block mining process.
	fmt.Printf("\nCreating Block and adding it to the Blockchain.\nHash crypto level %d applied. This may take a few moments/minutes. Please wait...", c.Mining.Difficulty)
	// Set process start time.
	miningStart := time.Now()
	// Set Block Header data.
	b.Index = lb.Index + 1
	b.Miner = w.Name
	b.MinerReward = c.Rewards.MinerReward
	b.PreviousHash = lb.Hash
	b.Nonce = 0
	b.Difficulty = c.Mining.Difficulty
	b.Timestamp = time.Now()
	b.MerkleRoot, err = utils.DeriveMerkleRootHash(merkleHashes)
	if err != nil {
		return err
	}

	b.Hash = [32]byte{}
	for {
		// Calculate the Hash.
		ProposedHash := b.CalculateHash()
		// Compare to see if it complies with set Dificulty level.
		if bytes.Equal(ProposedHash[0:c.Mining.Difficulty], targetHash[0:c.Mining.Difficulty]) {
			b.Hash = ProposedHash
			bc.Chain = append(bc.Chain, b)
			_ = b.WriteBlock()
			break
		}
		// Increment Nonce by one and try again.
		b.Nonce++
	}
	// Flag pending processes as processed.
	for _, h := range processedTrxHashes {
		for i, d := range bc.PendingData {
			if d.Hash == h && !d.Processed {
				d.Status = "Completed"
				d.Processed = true
				bc.PendingData[i] = d
				d.WritePendingData()
			}
		}
	}

	// Get mining process duration and notify user.
	miningDuration := time.Since(miningStart)
	fmt.Printf("\n\nProcessing time: %s\nResulting Nonce: %d\nBlock %x added to Blockchain\n--\n", miningDuration, b.Nonce, b.Hash)

	return nil
}

// PendingDataPurge -- Remove previously processed pending transaction data.
func (bc *Blockchain) PendingDataPurge() error {
	var pendingTrxCount int = 0
	for {
		pendingTrxCount = 0
		for _, d := range bc.PendingData {
			if d.Processed {
				pendingTrxCount++
				if err := os.RemoveAll(filepath.Join(c.Datapaths.Pending, fmt.Sprintf("%x", d.Hash))); err != nil {
					return err
				}
			}
		}

		if pendingTrxCount == 0 {
			fmt.Println("No pending transaction to delete.")
			break
		}

		fmt.Printf("%d Pending transaction data records to purge:\n", pendingTrxCount)
		for i := 0; i < len(bc.PendingData); i++ {
			if bc.PendingData[i].Processed {
				fmt.Printf("%x\n", bc.PendingData[i].Hash)
				copy(bc.PendingData[i:], bc.PendingData[i+1:])
				bc.PendingData[len(bc.PendingData)-1] = Data{}
				bc.PendingData = bc.PendingData[:len(bc.PendingData)-1]
			}
		}
	}

	return nil
}

// GetAccountBalance --
func (bc *Blockchain) GetAccountBalance(account string, detail bool) error {
	var balance float64 = 0
	var count int = 0
	var found bool = false
	if detail {
		fmt.Printf(" # \tTime\t\t\t\tType\tFrom\tTo\t\tAmount\t\tBalance\t\tComment\n---\t----\t\t\t\t----\t----\t--\t\t------\t\t-------\t\t-------\n")
	}
	for _, b := range bc.Chain {
		for _, d := range b.Data {
			if d.Type == "SLC" {
				continue
			}
			if d.To == account {
				found = true
				count++
				balance += d.Amount
				if detail {
					fmt.Printf("%d.\t%s\t%s\t%s\t%s\t\t%0.2f\t\t%0.2f\t\t%s\n", count, d.Timestamp.Format(time.RFC3339), d.Type, d.From, d.To, d.Amount, balance, d.Comment)
				}
			}
			if d.From == account {
				found = true
				count++
				balance -= d.Amount
				if detail {
					fmt.Printf("%d.\t%s\t%s\t%s\t%s\t\t%0.2f\t\t%0.2f\t\t%s\n", count, d.Timestamp.Format(time.RFC3339), d.Type, d.From, d.To, d.Amount, balance, d.Comment)
				}
			}
		}
	}
	// Account not found.
	if !found {
		err := errors.New("account does not exist")
		return err
	}
	// Output detail or just balance amount.
	if !detail {
		fmt.Printf("\nBalance: %0.2f\n", balance)
	}

	return nil
}

func main() {
	// Display mascote. Why? Because I can... .
	utils.PutCurious()
	// Read configuration filer.-> removed
	Cfg, err := config.ReadConfig()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(&Cfg.Datapaths.Wallets)
	// Get User's login input.
	fmt.Printf("Login as: ")
	user, _ = utils.ConsoleReader.ReadString('\n')
	user = utils.CleanConsoleInput(user)
	fmt.Printf("Password: ")
	pwd, _ := utils.ConsoleReader.ReadString('\n')
	pwd = utils.CleanConsoleInput(pwd)
	// Verify credentials.
	lastlogin, err := w.VerifyLogin(user, pwd)
	if err != nil {
		fmt.Printf("Wrong user name or password: %s\nBye!\n", err)
		os.Exit(0)
	}
	// All good, so ... Greetings!
	utils.PutWelcome(w.RealName, w.Role, w.Bank.Name, w.Bank.Routing, w.Bank.Account, lastlogin, w.LastLogin)

	// Start here -- Until exit is selected ('0').
	for {
		selection = utils.ShowMenu(w.Role)

		switch selection {
		case "0":
			fmt.Printf("%s left at %s ... Bye!\n", w.Name, time.Now().Format(time.RFC3339))
			os.Exit(0)

		case "init":
			// Only admin is allowed.
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			// Check if User knows what he's doing.
			fmt.Printf("BE WARNED: This will permanently delete all previous data!\nType 'ok' to continue: ")
			whattodo, _ := utils.ConsoleReader.ReadString('\n')
			whattodo = utils.CleanConsoleInput(whattodo)
			if whattodo != "ok" {
				break
			}
			// Guess we know what we're doing.
			bc.createStarlenCoin()

		case "2":
			fmt.Printf("Deposit into StarlenCoin:\n\n")
			from = utils.CleanConsoleInput(w.Bank.Name)
			to = w.Name
			fmt.Printf("Amount: ")
			amount, _ = utils.ConsoleReader.ReadString('\n')
			amount = utils.CleanConsoleInput(amount)
			fmt.Printf("Comment: ")
			comment, _ = utils.ConsoleReader.ReadString('\n')
			comment = utils.CleanConsoleInput(comment)

			d.AddToPendingTransactionData(from, to, amount, comment, "DEP")

		case "3":
			// Prompted input
			fmt.Printf("\nEnter transactions:\n")
			for {
				from = w.Name
				fmt.Printf("\n----\nTo: ")
				to, _ = utils.ConsoleReader.ReadString('\n')
				to = utils.CleanConsoleInput(to)
				if to == "stop" {
					break
				}
				fmt.Printf("Amount: ")
				amount, _ = utils.ConsoleReader.ReadString('\n')
				amount = utils.CleanConsoleInput(amount)
				fmt.Printf("Comment: ")
				comment, _ = utils.ConsoleReader.ReadString('\n')
				comment = utils.CleanConsoleInput(comment)

				d.AddToPendingTransactionData(from, to, amount, comment, "TRX")
			}

		case "4":
			dataCount := 0

			if len(bc.PendingData) == 0 {
				fmt.Println("No pending transaction data.")
			} else {
				for i, d := range bc.PendingData {
					sig = "err"
					if err := d.VerifySignature(); err == nil {
						sig = "ok"
					}

					fmt.Printf("%d. %s From: %s To: %s Amount: %0.2f Comment: %s Time: %s Hash: %x [Sig: %x...%x][%s] [%t][%s]\n", i+1, d.Type, d.From, d.To, d.Amount, d.Comment, d.Timestamp.Format(time.RFC3339), d.Hash, d.Signature[0:2], d.Signature[len(d.Signature)-2:len(d.Signature)], sig, d.Processed, d.Status)
					if !d.Processed {
						dataCount++
					}
				}
			}
			fmt.Printf("\n%d Data Transactions recorded.\n%d To be processed\n\n", len(bc.PendingData), dataCount)

		case "5":
			fmt.Println("Mining...")
			if err := bc.MinePendingDataTransactions(); err != nil {
				fmt.Println(err)
			}

		case "6":
			// Output expanded blockchain.
			bc.FollowTheLinks("display")

		case "hash verify":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			fmt.Printf("\nHash verification:\n\n")
			brokenBlocks := bc.HashVerification()
			if len(brokenBlocks) == 0 {
				fmt.Println("No hash link errors.")
			} else {
				for h, block := range brokenBlocks {
					fmt.Printf("[Index: %d] Wrong hash - Calculated: %x - Stored: %x\n", block.Index, h, block.Hash)
				}
			}

		case "7":
			var name string
			if w.Role == "admin" {
				fmt.Printf("Account Balance\n\nEnter name of account [%s]: ", w.Name)
				name, _ = utils.ConsoleReader.ReadString('\n')
				name = utils.CleanConsoleInput(name)
				if len(name) == 0 {
					name = w.Name
				}
			} else {
				name = w.Name
			}

			fmt.Printf("Show transaction detail? [Y|n]: ")
			showDetail, _ := utils.ConsoleReader.ReadString('\n')
			showDetail = utils.CleanConsoleInput(showDetail)
			if len(showDetail) == 0 {
				showDetail = "y"
			}

			var detail bool = false
			if showDetail == "y" {
				detail = true
			}

			fmt.Printf("\n")
			if err := bc.GetAccountBalance(name, detail); err != nil {
				fmt.Printf("\n%s", err)
			}

		case "dump":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			fmt.Printf("Quick & Dirty chain dump:\n")
			for _, b := range bc.Chain {
				fmt.Printf("%d %s %x %x [%d]\n", b.Index, b.Timestamp.Format(time.RFC3339), b.PreviousHash, b.Hash, len(b.Data))
			}

		case "1":
			if err := bc.ReloadIteration(); err != nil {
				fmt.Printf("Reload error: %s\n", err)
			}

		case "register node":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			fmt.Printf("Register a Node:\n")
			fmt.Printf("Name: ")
			name, _ := utils.ConsoleReader.ReadString('\n')
			name = utils.CleanConsoleInput(name)
			fmt.Printf("URL: ")
			url, _ := utils.ConsoleReader.ReadString('\n')
			url = utils.CleanConsoleInput(url)

			n.Register(name, url)

		case "delete node":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			fmt.Printf("Deregister a Node:\n")
			fmt.Printf("Name: ")
			name, _ := utils.ConsoleReader.ReadString('\n')
			name = utils.CleanConsoleInput(name)

			if err := n.Deregister(name); err != nil {
				fmt.Printf("%s\n", err)
			}

		case "list nodes":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			fmt.Printf("List of Nodes:\n")

			for i, n := range bc.Nodes {
				fmt.Printf("%d. Name: %s\tURL: %s\tRecorded: %s\tActive: %t\n", i+1, n.Name, n.Url, n.Timestamp.Format(time.RFC3339), n.Active)
			}

		case "root":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			fmt.Printf("\nBlockchain root data:\n\n")
			fmt.Printf("Name: %s\n", bc.Name)
			fmt.Printf("Crypto name: %s\n", bc.Cryptoname)
			fmt.Printf("Number of Nodes: %d\n", len(bc.Nodes))
			fmt.Printf("Number of Blocks: %d\n", len(bc.Chain))
			fmt.Printf("Number of Pending Transaction Data records: %d\n", len(bc.PendingData))
			fmt.Printf("\nConfiguration data:\n\n")
			fmt.Printf("Owner(s)/Maintainer(s): %s\n", c.Owner.Name)
			fmt.Printf("URL: %s\n", c.Owner.Url)
			fmt.Printf("Contact: %s\n", c.Owner.Contact)
			fmt.Printf("Blockchain Data: %s\n", c.Datapaths.Blocks)
			fmt.Printf("Blockchain Pending Data: %s\n", c.Datapaths.Pending)
			fmt.Printf("Wallet Data: %s\n", c.Datapaths.Wallets)
			fmt.Printf("Max Bloksize: %d\n", c.Mining.Blocksize)
			fmt.Printf("Hash crypto level: %d\n", c.Mining.Difficulty)
			fmt.Printf("Miner reward: %0.5f\n", c.Rewards.MinerReward)
			fmt.Printf("Transaction fee: %0.5f\n", c.Rewards.TransactionFee)

		case "register wallet":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			fmt.Printf("Register a Wallet:\n\n")
			fmt.Printf("Name: ")
			name, _ := utils.ConsoleReader.ReadString('\n')
			name = utils.CleanConsoleInput(name)
			fmt.Printf("Real name: ")
			realname, _ := utils.ConsoleReader.ReadString('\n')
			realname = utils.CleanConsoleInput(realname)
			fmt.Printf("Role: ")
			role, _ := utils.ConsoleReader.ReadString('\n')
			role = utils.CleanConsoleInput(role)
			fmt.Printf("Email: ")
			email, _ := utils.ConsoleReader.ReadString('\n')
			email = utils.CleanConsoleInput(email)
			fmt.Printf("Phone: ")
			phone, _ := utils.ConsoleReader.ReadString('\n')
			phone = utils.CleanConsoleInput(phone)
			fmt.Printf("Bank name: ")
			bankname, _ := utils.ConsoleReader.ReadString('\n')
			bankname = utils.CleanConsoleInput(bankname)
			fmt.Printf("Bank routing: ")
			bankrouting, _ := utils.ConsoleReader.ReadString('\n')
			bankrouting = utils.CleanConsoleInput(bankrouting)
			fmt.Printf("Bank account: ")
			bankaccount, _ := utils.ConsoleReader.ReadString('\n')
			bankaccount = utils.CleanConsoleInput(bankaccount)
			fmt.Printf("Password: ")
			password, _ := utils.ConsoleReader.ReadString('\n')
			password = utils.CleanConsoleInput(password)

			if err := w.Register(name, realname, role, email, phone, bankname, bankrouting, bankaccount, password); err != nil {
				fmt.Printf("%s\n", err)
				break
			}
			fmt.Printf("OK\n")

		case "list wallets":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			if err := ws.LoadWallets(); err != nil {
				fmt.Println(err)
			}
			for i, w := range ws.Wallets {
				fmt.Printf("%d. Name: %s - Real Name: %s - Role: %s - Email: %s - Phone: %s - Last login: %s\n", i+1, w.Name, w.RealName, w.Role, w.Email, w.Phone, w.LastLogin)
			}

		case "remove pending":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			if err := bc.PendingDataPurge(); err != nil {
				fmt.Println(err)
			}

		case "set aactive":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			// Check if User knows what he's doing.
			fmt.Printf("BE WARNED: This will set all previous processed transactions back to 'pending' status!\nType 'ok' to continue: ")
			whattodo, _ := utils.ConsoleReader.ReadString('\n')
			whattodo = utils.CleanConsoleInput(whattodo)
			if whattodo != "ok" {
				break
			}
			for i := range bc.PendingData {
				bc.PendingData[i].Processed = false
				bc.PendingData[i].Status = "pending"
				if err := d.WritePendingData(); err != nil {
					fmt.Println("During set active:", err)
				}
			}

		case "certify":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				break
			}
			for _, b := range bc.Chain {
				b.Certify()
			}

		case "config":
			if w.Role != "admin" {
				fmt.Println("not authorized")
				// break
			}
			// Read configuration filer.-> removed

		case "whoami":
			fmt.Printf("Logged in as:\nAccount: %x\nUser: %s\nRole: %s\n\n", w.Account, w.Name, w.Role)
			fmt.Printf("Name: %s\nEmail: %s\nPhone: %s\n", w.RealName, w.Email, w.Phone)
			fmt.Printf("Bank: %s ::%s-%s::\n", w.Bank.Name, w.Bank.Routing, w.Bank.Account)
			fmt.Printf("Logged in at: %s\n", w.LastLogin)

		default:
			fmt.Printf("Selection: %s is not a valid command.", selection)
		}
	}
}
