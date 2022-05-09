package utils

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// functions:
// deriveMerkleRootHash: Calculate the root of a Merkle tree starting with data transactions in a block as leaves.
//
// Derive the root hash of a Merkle tree from the transaction data hashes added to a block.
//  - Note: Adjust for odd number of leaves: add duplicate of last one (it's a rule), making it even.
//
//  stop -----------> [12345555]          -> Merkle tree root.
//                    /        \
//                [1234]       [5555]
//                /    \       /   \
//             [12]   [34]   [55] [55]
//             [12]   [34]   [55]  ^
//             /  \   /  \   /  \
//            [1][2] [3][4] [5][5]
// start ---> [1][2] [3][4] [5] ^         ^ -> Duplicate hash to make leaf count even.
//
func DeriveMerkleRootHash(hashes [][32]byte) ([32]byte, error) {
	if len(hashes) == 0 {
		return [32]byte{}, errors.New("empty hash slice as argument to derive merkle root")
	}
	started := false
	for {
		// Left with one: Exit loop. Merkle tree root made.
		if started && len(hashes) == 1 {
			break
		}
		started = true
		//  Adjust for odd number of leaves.
		if len(hashes)%2 == 1 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		// Create combined (concatenated) hash of left and right, store sha256 of it in left and zero out right
		for i := 0; i < len(hashes); i += 2 {
			hashes[i] = sha256.Sum256([]byte(fmt.Sprintf("%x%x", hashes[i], hashes[i+1])))
			hashes[i+1] = [32]byte{}
		}
		// Deflate slice by removing zero hash values (see above).
		i := 0
		for {
			if hashes[i] == [32]byte{} {
				copy(hashes[i:], hashes[i+1:])
				hashes = hashes[:len(hashes)-1]
			}
			i++
			if i > len(hashes) {
				break
			}
		}
	}

	return hashes[0], nil
}
