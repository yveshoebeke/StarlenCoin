package blockchain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"starlencoin.com/packages/block"
	"starlencoin.com/packages/config"
	"starlencoin.com/packages/data"
	"starlencoin.com/packages/node"
	"starlencoin.com/packages/utils"
	"starlencoin.com/packages/wallets"
)

const (
	BLOCKCHAINNAME = "Starlen"     // Name of this blockchain.
	CRYPTONAME     = "StarlenCoin" // Name of the crypto currency.
)

var (
	c          config.Config
	b          block.Block
	targetHash = [32]byte{}
)

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
	Chain       []block.Block `json:"chain"`
	PendingData []data.Data   `json:"pendingdata"`
	Nodes       []node.Node   `json:"nodes"`
	Name        string        `json:"name"`
	Cryptoname  string        `json:"cryptoname"`
}

// createGenesisBlock -- Initializes everything.
func (bc *Blockchain) CreateStarlenCoin() error {
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
	d := data.Data{
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
	b := block.Block{
		Index:             0,
		Timestamp:         time.Now(),
		PreviousHash:      [32]byte{},
		Nonce:             0,
		Difficulty:        0,
		Confirmations:     0,
		BlockValue:        0,
		Miner:             wallets.Wallet.Name,
		MinerReward:       0,
		TransactionsFee:   0,
		TransactionsCount: 1,
		MerkleRoot:        merkleroot,
		Data:              []data.Data{d},
		Hash:              [32]byte{},
	}
	b.Hash = b.CalculateHash()
	bc.Chain = []block.Block{}
	bc.Chain = append(bc.Chain, b)
	_ = b.WriteBlock()
}

// GetLatesBlock - Retrieve latest (most recent) block in the chain.
func (bc *Blockchain) GetLatestBlock() block.Block {
	return bc.Chain[len(bc.Chain)-1]
}

// GetLastBlock - Find the last block in the blockchain, ie. the block that is not referenced by any of the previous blocks.
func (bc *Blockchain) GetLastBlock() (block.Block, error) {
	var lastBlock block.Block
	var prevHashNotFound bool
	// Check if Blockchain is empty
	if len(bc.Chain) == 0 {
		return block.Block{}, errors.New("Blockchain is empty")
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
		return block.Block{}, errors.New("Blockchain linkage error, no Block qualified as last Block")
	} else {
		return lastBlock, nil
	}
}

// ReadPreviousBlock - Follow the link to find the block whose calculated hash matches.
func (bc *Blockchain) ReadPreviousBlock(previousBlockHash [32]byte) (block.Block, error) {
	b := block.Block{}
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
		return block.Block{}, errors.New("Chain Broken at " + fmt.Sprintf("%x", savedHash))
	}
}

// // DisplayBlock -- Output Block and associated Data.
// func (b Block) DisplayBlock(BlockCollection map[string]block.Block, CollectionKeys []string) error {
// 	for _, k := range CollectionKeys {
// 		*b = BlockCollection[k]
// 		fmt.Printf("\nIndex: %d Time: %s Nonce: %d Difficulty: %d Block value: %0.2f\n", b.Index, b.Timestamp.Format(time.RFC3339), b.Nonce, b.Difficulty, b.BlockValue)
// 		fmt.Printf("\tMiner: %s MinerReward: %0.5f Transactions fee: %0.5f Number of transactions: %d\n", b.Miner, b.MinerReward, b.TransactionsFee, b.TransactionsCount)
// 		fmt.Printf("\t   PrevHash: %x\n", b.PreviousHash)
// 		fmt.Printf("\t       Hash: %x\n", b.Hash)
// 		fmt.Printf("\tMerkle Root: %x\n", b.MerkleRoot)
// 		fmt.Printf("\tTransaction Data:\n")
// 		for i, d := range b.Data {
// 			fmt.Printf("\t%d. Type: %s From: %s To: %s Amount: %0.2f TransactionFee: %0.5f Comment: %s Time: %s\n", i+1, d.Type, d.From, d.To, d.Amount, d.TransactionFee, d.Comment, d.Timestamp.Format(time.RFC3339))
// 			var verified string = "OK"
// 			if err := d.VerifySignature(); err != nil {
// 				verified = "ERR"
// 			}
// 			fmt.Printf("\t\tSignature: [%x ... %x][%s]\n", d.Signature[0:2], d.Signature[len(d.Signature)-2:len(d.Signature)], verified)
// 			fmt.Printf("\t\tProcessed: %t Status: %s\n", d.Processed, d.Status)
// 			fmt.Printf("\t\tHash: %x\n", d.Hash)
// 		}
// 	}

// 	return nil
// }

// FollowTheLinks -- POC of iterating from last -> Genesis block by following the links.
func (bc *Blockchain) FollowTheLinks(f string) error {
	var count int = 0
	BlockCollection := make(map[string]block.Block)
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
	var block block.Block
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
	var data data.Data
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
func (bc *Blockchain) HashVerification() map[[32]byte]block.Block {
	// Make error map -> [GeneratedHash]Block
	HashErrors := make(map[[32]byte]block.Block)
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
	b.Data = []data.Data{}  // Empty Data struct.
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
			b.Miner = string(wallets.Wallet.Account[:])
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
	b.Miner = wallets.Wallet.Name
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
				bc.PendingData[len(bc.PendingData)-1] = data.Data{}
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
