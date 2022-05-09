package config

import (
	"io/ioutil"
	"os"

	"github.com/BurntSushi/toml"
)

var CONFIGPATH = os.Getenv("BC_CONFIG_PATH") // Local example -> /Users/yves/Projects/StarlenCoin/data/config/config.json

// *************************************************************************************
// Config -- App configuration structure and methods (file format: TOML)
type Config struct {
	Title     string      `toml:"title"`
	Owner     OwnerInfo   `toml:"owner"`
	Datapaths DatapathCfg `toml:"datapaths"`
	Mining    MiningCfg   `toml:"mining"`
	Rewards   RewardsCfg  `toml:"rewards"`
}

type OwnerInfo struct {
	Name    string `toml:"name"`
	Url     string `toml:"url"`
	Contact string `toml:"contact"`
}

type DatapathCfg struct {
	Blocks     string `toml:"blocks"`
	Pending    string `toml:"pending"`
	Wallets    string `toml:"wallets"`
	PublicKeys string `toml:"publickeys"`
}

type MiningCfg struct {
	Blocksize  uint `toml:"blocksize"`
	Difficulty uint `toml:"difficulty"`
}

type RewardsCfg struct {
	MinerReward    float64 `toml:"minerreward"`
	TransactionFee float64 `toml:"transactionfee"`
}

func ReadConfig() (*Config, error) {
	var c *Config
	buf, err := ioutil.ReadFile(CONFIGPATH)
	if err != nil {
		return nil, err
	}

	cfg := string(buf)
	if _, err := toml.Decode(cfg, c); err != nil {
		return nil, err
	}

	return c, nil
}
