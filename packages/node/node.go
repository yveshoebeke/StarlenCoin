package node

import (
	"errors"
	"time"

	"starlencoin.com/packages/blockchain"
)

var bc blockchain.Blockchain

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
