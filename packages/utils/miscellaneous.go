package utils

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Console reader
var ConsoleReader = bufio.NewReader(os.Stdin)

// functions:
//		CleanConsoleInput: Removes trailing artifact from the console input (ie.: CR).
//		PutWelcome: Displays welcome message.
//		PutCurious: Displays curious dog looking over fence... .
//		ShowMenu: Displays available selections and waits for user selection.
//		clearScreen: Clears the console window.

// Removes trailing console control character (CR).
func CleanConsoleInput(s string) string {
	return strings.TrimSpace(s)
}

// Just fun.
func PutCurious() {
	clearScreen()
	fmt.Println("     ^ ^\n    (O o)\n__oOO(.)OOo__\n_____________")
}

// Welcome message
func PutWelcome(realName, role, bankName, bankRouting, bankAccount, lastLogin2 string, lastLogin time.Time) {
	clearScreen()
	fmt.Printf("\n+-------------------------+\n| Welcome to StarlenCoin! |\n+-------------------------+\n\n")
	// Welcome!
	fmt.Printf("Welcome back %s, logged in at: %s\n", realName, lastLogin)
	// Retrieve User's Role, Bank and Last login
	fmt.Printf("Role: %s\n", role)
	fmt.Printf("Bank: %s ::%s-%s::\n", bankName, bankRouting, bankAccount)
	fmt.Printf("Last login: %s\n", lastLogin2)
}

// Displays menu and accepts a selection (0 and > 7 -> exits).
func ShowMenu(role string) string {
	fmt.Printf("\n\n+-------------------------------------------------------------| %s |--+\n", time.Now().Format(time.RFC3339))
	fmt.Printf("  0. Exit (NoOp).\n")
	fmt.Printf("  1. Load Blockchain with saved Block and Transaction Data.\n")
	fmt.Printf("  2. Add StarlenCoins to my wallet.\n")
	fmt.Printf("  3. Add StarlenCoin Transaction Data to the blockchain manually.\n")
	fmt.Printf("  4. Show pending transaction data in StarlenCoin blockchain.\n")
	fmt.Printf("  5. Mine Pending Transaction Data.\n")
	fmt.Printf("  6. Display StarlenCoin blockchain array (Last Block to Genesis Block).\n")
	fmt.Printf("  7. Show an account balance.\n")
	fmt.Printf("  whoami?\n")
	if role == "admin" {
		fmt.Printf(" ............................................................................................\n")
		fmt.Printf(" - init:\tInitialize the blockchain, creates genesis block (Warning: destroys saved data!).\n\n")
		fmt.Printf(" - register node:\tRegister a Node.\n")
		fmt.Printf(" - delete node:\tDelete a Node.\n")
		fmt.Printf(" - list nodes:\tList Nodes.\n\n")
		fmt.Printf(" - register wallet:\tRegister a Wallet.\n")
		fmt.Printf(" - list wallets:\t\tList Wallets.\n\n")
		fmt.Printf(" - dump:\tBlockchain Dump.\n")
		fmt.Printf(" - root:\tBlockchain Root data.\n\n")
		fmt.Printf(" - certify:\tCertify all block hashes, merkle roots, trx hashes and signatures.\n")
		fmt.Printf(" - hash verify:\tHash Verification with recalculated hash for all blocks.\n\n")
		fmt.Printf(" Danger lurks below\n")
		fmt.Printf(" - remove pending:\tRemove Pending transactions that were processed.\n")
		fmt.Printf(" - set active:\t\tSet all pending trx back to not processed (Debugging tool).\n")
		fmt.Printf(" - config:\t\tReload the config file.\n")
	}
	fmt.Printf("+------------------------------------------------------------------------------------------+\n")
	fmt.Printf("Select: ")
	selection, _ := ConsoleReader.ReadString('\n')

	return CleanConsoleInput(selection)
}

// Clear console window.
func clearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}
