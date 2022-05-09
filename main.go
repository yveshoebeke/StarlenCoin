package main

import (
	"fmt"
	"os"
	"time"

	"starlencoin.com/packages/block"
	"starlencoin.com/packages/blockchain"
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
	// CONFIGPATH = os.Getenv("BC_CONFIG_PATH") // Local example -> /Users/yves/Projects/StarlenCoin/data/config/config.json
	// consoleReader             = bufio.NewReader(os.Stdin)   // Console reader
	targetHash                = [32]byte{}
	Cfg                       config.Config
	c                         config.Config
	ws                        wallets.Wallets
	w                         wallets.Wallet
	d                         data.Data
	b                         block.Block
	n                         node.Node
	bc                        blockchain.Blockchain
	from, to, amount, comment string
	selection, sig            string
	user                      string
)

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
			bc.CreateStarlenCoin()

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
