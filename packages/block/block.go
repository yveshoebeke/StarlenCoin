package block

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"starlencoin.com/packages/config"
	"starlencoin.com/packages/data"
	"starlencoin.com/packages/utils"
)

var (
	c   config.Config
	sig string
)

// *************************************************************************************
// Block --
//	Methods:
//		CalculateHash: Returns SHA256 hash of the block in JSON format.
//		MakeJSONString: Marshals Block structure into a JSON string.
//		WriteBlock: Writes the block to disk in JSON format with its hash as filename.
type Block struct {
	Index             uint        `json:"index"`
	Timestamp         time.Time   `json:"timestamp"`
	Nonce             uint        `json:"nonce"`
	Difficulty        uint        `json:"difficulty"`
	Confirmations     uint        `json:"confirmations"`
	PreviousHash      [32]byte    `json:"previoushash"`
	BlockValue        float64     `json:"blockvalue"`
	Miner             string      `json:"miner"`
	MinerReward       float64     `json:"minerreward"`
	TransactionsFee   float64     `json:"transactionsFee"`
	TransactionsCount uint        `json:"transactionscount"`
	MerkleRoot        [32]byte    `json:"merkleroot"`
	Data              []data.Data `json:"data"`
	Hash              [32]byte    `json:"hash"`
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

// DisplayBlock -- Output Block and associated Data.
func (b Block) DisplayBlock(BlockCollection map[string]Block, CollectionKeys []string) error {
	for _, k := range CollectionKeys {
		b = BlockCollection[k]
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
